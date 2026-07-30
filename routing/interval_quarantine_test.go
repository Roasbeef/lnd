package routing

import (
	"testing"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

// TestIntervalQuarantinePricesSoftly tests the property that separates a
// quarantined observation from a bound. A failure we cannot attribute makes an
// amount less attractive and never makes it impossible, because an impossible
// amount is never attempted and an attempt is the only thing that could show
// the suspicion was misplaced.
func TestIntervalQuarantinePricesSoftly(t *testing.T) {
	t.Parallel()

	capacity := testIntervalCapacity
	amt := capacity / 2

	store := NewIntervalStore(0)
	clean := store.Probability(testIntervalKey, amt, capacity)

	// One ambiguous failure naming three channels, so a third of the blame
	// lands here.
	store.RecordSuspectFailure(testIntervalKey, amt, capacity, 1.0/3)

	interval := store.Get(testIntervalKey, capacity)
	require.Equal(t, amt, interval.SuspectAmt)
	require.InDelta(t, 1.0/3, interval.SuspectWeight, 1e-9)

	// The bounds are untouched, which is the whole point of the quarantine.
	require.Zero(t, interval.UpperFail)

	// The amount is discounted but still reachable.
	suspected := store.Probability(testIntervalKey, amt, capacity)
	require.Less(t, suspected, clean)
	require.Greater(t, suspected, 0.0)

	// Only the amount the failure named, and larger ones, are discounted. A
	// smaller amount is untouched, since nothing was said against it.
	require.Equal(
		t, store.Probability(testIntervalKey, amt/4, capacity),
		NewIntervalStore(0).Probability(testIntervalKey, amt/4, capacity),
	)
	require.Less(
		t, store.Probability(testIntervalKey, amt*3/2, capacity),
		clean,
	)

	// More agreement discounts harder, without ever reaching zero.
	previous := suspected
	for i := 0; i < 3; i++ {
		store.RecordSuspectFailure(
			testIntervalKey, amt, capacity, 1.0/3,
		)

		current := store.Probability(testIntervalKey, amt, capacity)
		if store.Get(testIntervalKey, capacity).SuspectAmt == 0 {
			// Promoted, which the next test covers.
			break
		}

		require.LessOrEqual(t, current, previous)
		require.Greater(t, current, 0.0)
		previous = current
	}
}

// TestIntervalQuarantinePromotes tests that agreement convicts. Enough
// independent failures naming the same channel and the same amount turn the
// suspicion into an ordinary upper bound, at which point it prices like any
// other thing we have watched fail.
func TestIntervalQuarantinePromotes(t *testing.T) {
	t.Parallel()

	capacity := testIntervalCapacity
	amt := capacity / 2

	store := NewIntervalStore(0)

	// Failures naming two suspects each, so half the blame lands here every
	// time. Three of them clear the promotion threshold.
	for i := 0; i < 2; i++ {
		store.RecordSuspectFailure(testIntervalKey, amt, capacity, 0.5)

		require.NotZero(
			t, store.Get(testIntervalKey, capacity).SuspectAmt,
			"convicted on %d reports", i+1,
		)
		require.Zero(t, store.Get(testIntervalKey, capacity).UpperFail)
	}

	store.RecordSuspectFailure(testIntervalKey, amt, capacity, 1.05)

	// Convicted. The suspicion is now a bound, and the quarantine that held
	// it is empty, since from here the bound is what speaks.
	interval := store.Get(testIntervalKey, capacity)
	require.Equal(t, amt, interval.UpperFail)
	require.Zero(t, interval.SuspectAmt)
	require.Zero(t, interval.SuspectWeight)
	require.Less(t, interval.Estimate, amt)

	// And it prices as a bound does.
	require.Zero(t, store.Probability(testIntervalKey, amt, capacity))
}

// TestIntervalQuarantinePromotesAtSmallestAmount tests that the quarantine
// keeps the tightest amount it has been shown, so that a conviction bounds the
// channel where the evidence actually put it.
func TestIntervalQuarantinePromotesAtSmallestAmount(t *testing.T) {
	t.Parallel()

	capacity := testIntervalCapacity

	store := NewIntervalStore(0)
	store.RecordSuspectFailure(testIntervalKey, capacity/2, capacity, 1.0)
	store.RecordSuspectFailure(testIntervalKey, capacity/4, capacity, 1.0)

	require.Equal(
		t, capacity/4, store.Get(testIntervalKey, capacity).SuspectAmt,
	)

	store.RecordSuspectFailure(testIntervalKey, capacity/2, capacity, 1.0)

	require.Equal(
		t, capacity/4, store.Get(testIntervalKey, capacity).UpperFail,
	)
}

// TestIntervalQuarantineClearsOnContradiction tests that watching the channel
// do the thing it was suspected of failing drops the suspicion outright. This
// is what keeps an ambiguous failure from poisoning a channel that was never at
// fault.
func TestIntervalQuarantineClearsOnContradiction(t *testing.T) {
	t.Parallel()

	capacity := testIntervalCapacity
	amt := capacity / 2

	// A probe of the suspected amount clears it.
	store := NewIntervalStore(0)
	store.RecordSuspectFailure(testIntervalKey, amt, capacity, 1.0)
	store.RecordProbe(testIntervalKey, amt, capacity)

	interval := store.Get(testIntervalKey, capacity)
	require.Zero(t, interval.SuspectAmt)
	require.Zero(t, interval.SuspectWeight)
	require.EqualValues(
		t, intervalProvenProbability,
		store.Probability(testIntervalKey, amt, capacity),
	)

	// So does a probe of more than the suspected amount.
	store = NewIntervalStore(0)
	store.RecordSuspectFailure(testIntervalKey, amt, capacity, 1.0)
	store.RecordProbe(testIntervalKey, amt*3/2, capacity)
	require.Zero(t, store.Get(testIntervalKey, capacity).SuspectAmt)

	// A probe of less does not, since it says nothing about the amount the
	// failure named.
	store = NewIntervalStore(0)
	store.RecordSuspectFailure(testIntervalKey, amt, capacity, 1.0)
	store.RecordProbe(testIntervalKey, amt/4, capacity)
	require.Equal(
		t, amt, store.Get(testIntervalKey, capacity).SuspectAmt,
	)

	// A settlement clears it too, since a settlement is a stronger form of
	// the same contradiction.
	store = NewIntervalStore(0)
	store.RecordSuspectFailure(testIntervalKey, amt, capacity, 1.0)
	store.RecordProbe(testIntervalKey, amt, capacity)
	store.RecordSettlement(testIntervalKey, amt/10, capacity)
	require.Zero(t, store.Get(testIntervalKey, capacity).SuspectAmt)

	// A suspicion about an amount we have already proven is never held in
	// the first place.
	store = NewIntervalStore(0)
	store.RecordProbe(testIntervalKey, amt, capacity)
	store.RecordSuspectFailure(testIntervalKey, amt/2, capacity, 1.0)
	require.Zero(t, store.Get(testIntervalKey, capacity).SuspectAmt)
}

// TestIntervalQuarantineSubsumedByBound tests that a failure we do trust
// swallows a suspicion reaching for the same thing, so that the two do not
// discount the same amount twice over.
func TestIntervalQuarantineSubsumedByBound(t *testing.T) {
	t.Parallel()

	capacity := testIntervalCapacity
	amt := capacity / 2

	store := NewIntervalStore(0)
	store.RecordSuspectFailure(testIntervalKey, amt, capacity, 1.0)
	store.RecordFailure(testIntervalKey, amt/2, capacity)

	interval := store.Get(testIntervalKey, capacity)
	require.Equal(t, amt/2, interval.UpperFail)
	require.Zero(t, interval.SuspectAmt)
}

// TestIntervalQuarantineWritesOneDirection tests that an ambiguous failure says
// nothing about the other side of the channel. The inference that liquidity
// missing here is liquidity present there only holds when we know the failure
// happened here.
func TestIntervalQuarantineWritesOneDirection(t *testing.T) {
	t.Parallel()

	capacity := testIntervalCapacity

	store := NewIntervalStore(0)
	store.RecordSuspectFailure(
		testIntervalKey, capacity/2, capacity, 1.0,
	)

	reverse := store.Get(testIntervalKey.Reverse(), capacity)
	require.False(t, reverse.Known)
	require.Zero(t, reverse.LowerOK)
	require.Zero(t, reverse.SuspectAmt)
}

// TestIntervalQuarantineIgnoresUninformative tests that a quarantine entry is
// only made when there is something to record.
func TestIntervalQuarantineIgnoresUninformative(t *testing.T) {
	t.Parallel()

	store := NewIntervalStore(0)

	store.RecordSuspectFailure(testIntervalKey, 0, testIntervalCapacity, 1)
	store.RecordSuspectFailure(testIntervalKey, 100, 0, 1)
	store.RecordSuspectFailure(testIntervalKey, 100, testIntervalCapacity, 0)

	require.Zero(t, store.Len())
}

// TestIntervalSessionQuarantinesAmbiguousFailure tests the path a real payment
// takes. A failure nobody claims, over a route with several plausible culprits,
// leaves a discount on each of them and a bound on none.
func TestIntervalSessionQuarantinesAmbiguousFailure(t *testing.T) {
	t.Parallel()

	const capacitySat = 100_000

	graph := newIntervalTestGraph(t, []byte{firstRelayID}, capacitySat)
	amt := lnwire.NewMSatFromSatoshis(40_000)
	ctx := newIntervalTestCtx(t, graph, amt, 1, false)

	rt, err := ctx.session.RequestRoute(
		amt, lnwire.MaxMilliSatoshi, 0, 0, nil,
	)
	require.NoError(t, err)
	require.Len(t, rt.Hops, 2)

	// A failure with no source and no message, which is what an unreadable
	// onion error looks like by the time it reaches us.
	ctx.session.ReportAttemptFailure(0, rt, nil, nil)

	// Our own first hop is never a suspect, so the only channel that could
	// be blamed is the interior one, and a single suspect is an elimination
	// rather than a guess: that one is bounded outright.
	interior := IntervalKey{
		ChanID: 2,
		From:   createPubkey(firstRelayID),
		To:     createPubkey(targetNodeID),
	}
	capacity := lnwire.NewMSatFromSatoshis(capacitySat)
	require.NotZero(t, ctx.store.Get(interior, capacity).UpperFail)

	// Now the ambiguous case, over a route with two channels neither of
	// which is ours.
	session, store := newCorridorSession(
		t, lnwire.NewMSatFromSatoshis(600_000), 1,
	)
	longRoute := &route.Route{
		TotalAmount:  600_000_000,
		SourcePubKey: createPubkey(sourceNodeID),
		Hops: []*route.Hop{
			{
				PubKeyBytes:  createPubkey(firstRelayID),
				ChannelID:    1,
				AmtToForward: 600_000_000,
			},
			{
				PubKeyBytes:  createPubkey(secondRelayID),
				ChannelID:    9,
				AmtToForward: 600_000_000,
			},
			{
				PubKeyBytes:  createPubkey(targetNodeID),
				ChannelID:    4,
				AmtToForward: 600_000_000,
			},
		},
	}

	// The session has to know the capacities to record anything, which it
	// normally learns while path finding.
	capacity = lnwire.NewMSatFromSatoshis(budgetCapacity)
	for _, key := range intervalRouteKeys(longRoute) {
		session.capacities[key] = capacity
	}

	session.ReportAttemptFailure(0, longRoute, nil, nil)

	// Two suspects, so each carries a quarantined discount and neither
	// carries a bound.
	suspects := []IntervalKey{
		{
			ChanID: 9,
			From:   createPubkey(firstRelayID),
			To:     createPubkey(secondRelayID),
		},
		{
			ChanID: 4,
			From:   createPubkey(secondRelayID),
			To:     createPubkey(targetNodeID),
		},
	}

	for _, key := range suspects {
		interval := store.Get(key, capacity)

		require.NotZero(t, interval.SuspectAmt, "no suspicion on %v",
			key.ChanID)
		require.Zero(t, interval.UpperFail, "bound placed on %v by an "+
			"ambiguous failure", key.ChanID)
		require.Greater(
			t, store.Probability(key, 600_000_000, capacity), 0.0,
		)
	}
}

// TestIntervalQuarantineSeverable tests that the quarantine can be switched off
// without touching anything else. It measured as a null on the tiers built to
// reward it, so whether it ships is a decision somebody should be able to make
// with a config field rather than a patch.
func TestIntervalQuarantineSeverable(t *testing.T) {
	t.Parallel()

	// The zero value keeps the mechanism on, which is the behaviour every
	// published measurement of this router was taken with.
	require.False(t, IntervalConfig{}.DisableQuarantine)
	require.False(t, DefaultIntervalConfig().DisableQuarantine)

	route := func(disabled bool) (*IntervalStore, []IntervalKey) {
		session, store := newCorridorSession(
			t, lnwire.NewMSatFromSatoshis(600_000), 1,
		)
		session.cfg.DisableQuarantine = disabled

		// A route with two hops that are not ours, so an unattributable
		// failure over it has two suspects and neither can be named.
		rt := &route.Route{
			TotalAmount:  600_000_000,
			SourcePubKey: createPubkey(sourceNodeID),
			Hops: []*route.Hop{
				{
					PubKeyBytes:  createPubkey(firstRelayID),
					ChannelID:    1,
					AmtToForward: 600_000_000,
				},
				{
					PubKeyBytes: createPubkey(
						secondRelayID,
					),
					ChannelID:    9,
					AmtToForward: 600_000_000,
				},
				{
					PubKeyBytes:  createPubkey(targetNodeID),
					ChannelID:    4,
					AmtToForward: 600_000_000,
				},
			},
		}

		keys := intervalRouteKeys(rt)
		for _, key := range keys {
			session.capacities[key] = lnwire.NewMSatFromSatoshis(
				budgetCapacity,
			)
		}

		session.ReportAttemptFailure(0, rt, nil, nil)

		return store, keys
	}

	capacity := lnwire.NewMSatFromSatoshis(budgetCapacity)

	// On, the suspects carry a discount.
	store, keys := route(false)

	var suspected int
	for _, key := range keys {
		if store.Get(key, capacity).SuspectAmt != 0 {
			suspected++
		}
	}
	require.NotZero(t, suspected)

	// Off, the store hears nothing at all. Nothing is recorded, so nothing
	// prices, and the payment falls back to handling the failure with the
	// penalties that live and die with it.
	store, keys = route(true)

	require.Zero(t, store.Len())
	for _, key := range keys {
		interval := store.Get(key, capacity)

		require.Zero(t, interval.SuspectAmt)
		require.Zero(t, interval.SuspectWeight)
		require.False(t, interval.Known)
	}
}
