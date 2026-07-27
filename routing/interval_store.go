package routing

import (
	"sort"
	"sync"

	"github.com/lightningnetwork/lnd/lnwire"
)

// DefaultMaxIntervalHistory is the default number of directed channels the
// interval store will remember. Entries are created in pairs, one per
// direction, so this is roughly half as many channels. Mission control bounds
// its own history the same way, for the same reason: a long lived node would
// otherwise accumulate an entry for every channel it has ever touched.
const DefaultMaxIntervalHistory = 10000

// intervalEvictionFraction is the fraction of the store dropped when it grows
// past its bound. Evicting a batch rather than a single entry keeps the cost of
// eviction amortized rather than paid on every insert once the store is full.
const intervalEvictionFraction = 4

// intervalEntry is one directed channel's belief plus the bookkeeping the store
// needs to bound itself.
type intervalEntry struct {
	LiquidityInterval

	// seq is the value of the store's counter when this entry was last
	// written, which is what eviction orders on.
	seq uint64
}

// IntervalStore holds the router's belief about the liquidity of every directed
// channel it has observed. It plays the role mission control plays for the
// stock router, with two differences that matter. It records amount intervals
// rather than penalties, and it never forgets anything on a timer: a bound
// moves when new evidence arrives, not when a half life elapses.
//
// The store lives for as long as the node does and is shared by every payment,
// which is what makes the beliefs one payment gathers available to the next.
//
// NOTE: the store is held in memory only. Persisting it across restarts is
// future work, and it would need care: an interval restored from disk describes
// a network state that may no longer exist, and a hard upper bound has no way
// back once it is wrong. A persisted bound should clamp to a small probability
// rather than to zero.
type IntervalStore struct {
	mu sync.Mutex

	// entries holds one belief per directed channel.
	entries map[IntervalKey]*intervalEntry

	// maxEntries bounds the size of the store.
	maxEntries int

	// seq is a monotonic counter used to order entries for eviction.
	seq uint64
}

// NewIntervalStore builds an empty store bounded at the given number of
// directed channels. A non-positive bound selects the default.
func NewIntervalStore(maxEntries int) *IntervalStore {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxIntervalHistory
	}

	return &IntervalStore{
		entries:    make(map[IntervalKey]*intervalEntry),
		maxEntries: maxEntries,
	}
}

// Get returns the belief held for the given directed channel, normalized
// against the given capacity. A channel that has never been observed returns
// the zero interval, which the probability model reads as "no evidence".
func (s *IntervalStore) Get(key IntervalKey,
	capacity lnwire.MilliSatoshi) LiquidityInterval {

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok {
		return LiquidityInterval{}
	}

	interval := entry.LiquidityInterval
	interval.normalize(capacity)

	return interval
}

// Probability returns the success probability of forwarding the given amount
// over the given directed channel.
func (s *IntervalStore) Probability(key IntervalKey,
	amt, capacity lnwire.MilliSatoshi) float64 {

	interval := s.Get(key, capacity)

	return interval.Probability(amt, capacity)
}

// RecordProbe records that the given directed channel forwarded the given
// amount, which we learn whenever a failure is reported by a node further along
// the route than this hop.
func (s *IntervalStore) RecordProbe(key IntervalKey,
	amt, capacity lnwire.MilliSatoshi) {

	s.update(key, amt, capacity, func(forward, reverse *LiquidityInterval,
		amt lnwire.MilliSatoshi) {

		forward.recordProbe(reverse, amt, capacity)
	})
}

// RecordFailure records that the given directed channel could not carry the
// given amount.
func (s *IntervalStore) RecordFailure(key IntervalKey,
	amt, capacity lnwire.MilliSatoshi) {

	s.update(key, amt, capacity, func(forward, reverse *LiquidityInterval,
		amt lnwire.MilliSatoshi) {

		forward.recordFailure(reverse, amt, capacity)
	})
}

// RecordSettlement records that the given directed channel actually moved the
// given amount, which shifts both directions of the interval rather than merely
// narrowing them.
func (s *IntervalStore) RecordSettlement(key IntervalKey,
	amt, capacity lnwire.MilliSatoshi) {

	s.update(key, amt, capacity, func(forward, reverse *LiquidityInterval,
		amt lnwire.MilliSatoshi) {

		forward.recordSettlement(reverse, amt, capacity)
	})
}

// update applies an observation to both directions of a channel under the
// store's lock. Observations of a zero amount, or of a channel whose capacity
// we do not know, carry no information the model can use and are dropped. The
// sanitized amount is handed to the callback, which must use it in place of the
// amount its caller was given.
func (s *IntervalStore) update(key IntervalKey, amt,
	capacity lnwire.MilliSatoshi,
	apply func(forward, reverse *LiquidityInterval,
		amt lnwire.MilliSatoshi)) {

	if amt == 0 || capacity == 0 {
		return
	}

	// An amount larger than the capacity cannot be a real observation about
	// this channel. It can still reach us, because the capacity we path
	// find against is a synthetic one when a peer has several channels to
	// the same node, so clamp rather than reject.
	if amt > capacity {
		amt = capacity
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	forward := s.entryLocked(key)
	reverse := s.entryLocked(key.Reverse())

	apply(&forward.LiquidityInterval, &reverse.LiquidityInterval, amt)

	s.evictLocked()
}

// entryLocked returns the entry for a key, creating it if needed, and stamps it
// as the most recently written.
//
// NOTE: the store's mutex must be held.
func (s *IntervalStore) entryLocked(key IntervalKey) *intervalEntry {
	entry, ok := s.entries[key]
	if !ok {
		entry = &intervalEntry{}
		s.entries[key] = entry
	}

	s.seq++
	entry.seq = s.seq

	return entry
}

// evictLocked drops the least recently written entries when the store has grown
// past its bound.
//
// NOTE: the store's mutex must be held.
func (s *IntervalStore) evictLocked() {
	if len(s.entries) <= s.maxEntries {
		return
	}

	keys := make([]IntervalKey, 0, len(s.entries))
	for key := range s.entries {
		keys = append(keys, key)
	}

	sort.Slice(keys, func(i, j int) bool {
		return s.entries[keys[i]].seq < s.entries[keys[j]].seq
	})

	drop := len(s.entries) / intervalEvictionFraction
	for _, key := range keys[:drop] {
		delete(s.entries, key)
	}
}

// Restore seeds the store with a belief that was held before this process
// started. The interval is taken as it was written down, but it is marked as
// restored, which stops the probability model from treating either of its
// bounds as a certainty until a fresh observation replaces it.
//
// An entry that has already been observed in this process is left alone, since
// what we have watched ourselves beats anything we read back.
func (s *IntervalStore) Restore(key IntervalKey,
	interval LiquidityInterval) {

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.entries[key]; ok && existing.Known &&
		!existing.Restored {

		return
	}

	entry := s.entryLocked(key)
	entry.LiquidityInterval = interval
	entry.Known = true
	entry.markRestored()

	s.evictLocked()
}

// ForEach hands every belief the store holds to the callback, which is how a
// persistence layer reads out what needs writing down.
func (s *IntervalStore) ForEach(cb func(IntervalKey, LiquidityInterval)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, entry := range s.entries {
		cb(key, entry.LiquidityInterval)
	}
}

// Clear forgets everything the store has learned. It exists so that an operator
// can reset the router's beliefs the way mission control's history can be
// reset.
func (s *IntervalStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries = make(map[IntervalKey]*intervalEntry)
	s.seq = 0
}

// Len returns the number of directed channels the store currently holds a
// belief for.
func (s *IntervalStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.entries)
}
