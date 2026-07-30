package routing

import (
	"math"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

// The budget tests run over two corridors that differ in exactly two ways: one
// is free and unproven, the other charges a fee and has been watched carry the
// amount. Which one the session picks is then a pure statement about how it
// prices reliability against money.
const (
	// budgetCapacity is the capacity of every channel in the corridors.
	budgetCapacity = btcutil.Amount(1_000_000)

	// budgetAmount is the amount paid, a tenth of a channel.
	budgetAmount = lnwire.MilliSatoshi(100_000_000)

	// budgetHopFee is what the expensive corridor charges to forward.
	budgetHopFee = lnwire.MilliSatoshi(200_000)
)

// newBudgetSession builds a session over a free corridor through the first
// relay and a paying corridor through the second, and proves the paying one by
// recording that it has carried the amount.
func newBudgetSession(t *testing.T) (*intervalPaymentSession, IntervalKey) {
	t.Helper()

	var (
		source = createPubkey(sourceNodeID)
		cheap  = createPubkey(firstRelayID)
		dear   = createPubkey(secondRelayID)
		target = createPubkey(targetNodeID)
	)

	graph := &parallelGraph{
		channels: []parallelChannel{
			{
				id: 1, node1: source, node2: cheap,
				capacity: budgetCapacity,
			},
			{
				id: 2, node1: cheap, node2: target,
				capacity: budgetCapacity,
			},
			{
				id: 3, node1: source, node2: dear,
				capacity: budgetCapacity,
			},
			{
				id: 4, node1: dear, node2: target,
				capacity: budgetCapacity, baseFee: budgetHopFee,
			},
		},
	}

	var paymentAddr [32]byte
	payment := &LightningPayment{
		FinalCLTVDelta: 40,
		FeeLimit:       lnwire.MaxMilliSatoshi,
		Target:         target,
		PaymentAddr:    fn.Some(paymentAddr),
		Amount:         budgetAmount,
		CltvLimit:      math.MaxUint32,
		MaxParts:       1,
		DestFeatures: lnwire.NewFeatureVector(
			lnwire.NewRawFeatureVector(
				lnwire.TLVOnionPayloadOptional,
				lnwire.PaymentAddrOptional,
				lnwire.MPPOptional,
			), lnwire.Features,
		),
	}
	require.NoError(t, payment.SetPaymentHash([32]byte{}))

	getBandwidthHints := func(_ Graph) (bandwidthHints, error) {
		return &mockBandwidthHints{
			hints: map[uint64]lnwire.MilliSatoshi{
				1: lnwire.NewMSatFromSatoshis(budgetCapacity),
				3: lnwire.NewMSatFromSatoshis(budgetCapacity),
			},
		}, nil
	}

	store := NewIntervalStore(0)

	// The paying corridor's interior hop has been watched carry the amount,
	// so it is near certain where the free corridor is only a guess.
	proven := IntervalKey{ChanID: 4, From: dear, To: target}
	store.RecordProbe(
		proven, budgetAmount,
		lnwire.NewMSatFromSatoshis(budgetCapacity),
	)

	session, err := newIntervalPaymentSession(
		payment, source, getBandwidthHints, graph, store,
		DefaultIntervalConfig(),
	)
	require.NoError(t, err)

	return session, proven
}

// TestIntervalFeePricePerNat tests the exchange rate that decides whether a fee
// budget can influence the search at all. The units are the finding here: a
// rate proportional to the amount can never be reached by a realistic budget,
// while an absolute rate can.
func TestIntervalFeePricePerNat(t *testing.T) {
	t.Parallel()

	amt := lnwire.MilliSatoshi(1_000_000_000)

	// With no budget the rate is a fraction of the amount, which reproduces
	// the behaviour this design was validated with.
	noBudget := intervalFeePricePerNat(
		lnwire.MaxMilliSatoshi, amt, intervalFeeWeight,
	)
	require.Equal(t, float64(amt)/intervalFeeWeight, noBudget)

	// Read as a price that is a fifth of the payment, which no fee budget
	// anybody would set comes close to. That is the whole reason it never
	// binds.
	require.Greater(t, noBudget, float64(amt)/10)

	// With a budget the rate is absolute and derived from what is left.
	budget := lnwire.MilliSatoshi(400_000)
	priced := intervalFeePricePerNat(budget, amt, intervalFeeWeight)
	require.Equal(t, float64(budget)/intervalBudgetShare, priced)

	// The rate falls as the budget is spent, so a payment running low
	// prices reliability ever more cheaply and stops paying up for it.
	previous := math.MaxFloat64
	for _, left := range []lnwire.MilliSatoshi{
		800_000, 400_000, 200_000, 120_000,
	} {
		current := intervalFeePricePerNat(left, amt, intervalFeeWeight)
		require.Less(t, current, previous)
		previous = current
	}

	// The rate is bounded at both ends. A payment with almost nothing left
	// still pays something, since a route it can afford beats no route.
	require.Equal(
		t, intervalMinFeePrice,
		intervalFeePricePerNat(1, amt, intervalFeeWeight),
	)
	require.Equal(
		t, intervalMaxFeePrice, intervalFeePricePerNat(
			lnwire.MaxMilliSatoshi-1, amt, intervalFeeWeight,
		),
	)

	// Because the rate is absolute, its ceiling in relative terms tightens
	// as the payment grows, which is the direction a budget quoted in parts
	// per million needs.
	small := lnwire.MilliSatoshi(1_000_000)
	large := lnwire.MilliSatoshi(1_000_000_000)
	rate := intervalFeePricePerNat(budget, 0, intervalFeeWeight)

	require.Greater(t, rate/float64(small), rate/float64(large))
}

// TestIntervalBudgetPicksCheapCorridor tests that a binding budget changes the
// route. With money effectively free the session buys the reliability it has
// evidence for, and with a budget tight enough that the same reliability costs
// more than it is worth, the session takes the cheap corridor instead.
func TestIntervalBudgetPicksCheapCorridor(t *testing.T) {
	t.Parallel()

	var (
		cheap = createPubkey(firstRelayID)
		dear  = createPubkey(secondRelayID)
	)

	// With no budget the fee term is a rounding error against the risk of
	// an unproven corridor, so the proven one wins.
	session, _ := newBudgetSession(t)

	rt, err := session.RequestRoute(
		budgetAmount, lnwire.MaxMilliSatoshi, 0, 0, nil,
	)
	require.NoError(t, err)
	require.Equal(t, dear, rt.Hops[0].PubKeyBytes)
	require.EqualValues(t, budgetHopFee, rt.TotalAmount-budgetAmount)

	// Now hand the same session the same choice with a budget that can
	// still afford the paying corridor twice over, but under which one nat
	// of reliability is no longer worth what that corridor charges.
	session, _ = newBudgetSession(t)

	rt, err = session.RequestRoute(budgetAmount, budgetHopFee*2, 0, 0, nil)
	require.NoError(t, err)
	require.Equal(t, cheap, rt.Hops[0].PubKeyBytes)
	require.Zero(t, rt.TotalAmount-budgetAmount)
}

// TestIntervalBudgetNeverExceeded tests the discipline lnd's own session has
// and this one must match: no route is ever returned that the payment cannot
// afford, at any budget.
func TestIntervalBudgetNeverExceeded(t *testing.T) {
	t.Parallel()

	limits := []lnwire.MilliSatoshi{
		lnwire.MaxMilliSatoshi, budgetHopFee * 4, budgetHopFee * 2,
		budgetHopFee, budgetHopFee - 1, budgetHopFee / 2, 1,
	}

	for _, limit := range limits {
		session, _ := newBudgetSession(t)

		rt, err := session.RequestRoute(budgetAmount, limit, 0, 0, nil)
		if err != nil {
			require.ErrorIs(t, err, errNoPathFound)

			continue
		}

		fee := rt.TotalAmount - budgetAmount
		require.LessOrEqual(t, fee, limit,
			"returned a route costing %v under a limit of %v",
			fee, limit)
	}

	// A budget too small for even the free corridor's zero fee is still
	// routable, since the free corridor costs nothing.
	session, _ := newBudgetSession(t)
	rt, err := session.RequestRoute(budgetAmount, 0, 0, 0, nil)
	require.NoError(t, err)
	require.Zero(t, rt.TotalAmount-budgetAmount)
}

// TestIntervalFrontierKeepsCheapestLabel tests that the search never throws
// away the cheapest way out of a node. A frontier that fills with reliable
// expensive labels leaves a payment that cannot afford them with nothing, which
// is the failure the budget work exists to prevent.
func TestIntervalFrontierKeepsCheapestLabel(t *testing.T) {
	t.Parallel()

	const deliver = lnwire.MilliSatoshi(1_000_000)

	node := route.Vertex{1}
	frontier := &intervalFrontier{
		labels:    map[route.Vertex][]*intervalLabel{},
		maxLabels: 3,
	}

	// The cheapest label is also the worst scoring one, so every rule but
	// this one would evict it.
	cheapest := &intervalLabel{
		node:              node,
		netAmountReceived: deliver,
		score:             100,
		hops:              1,
	}
	require.True(t, frontier.insert(cheapest, deliver))

	// Fill the node with labels that score better and cost more. Score
	// falls as the amount rises across the set, so no label dominates
	// another and every one of them is a genuine trade-off the search would
	// want to keep.
	for i := 1; i <= 6; i++ {
		frontier.insert(&intervalLabel{
			node:              node,
			netAmountReceived: deliver * lnwire.MilliSatoshi(10+i),
			score:             float64(10 - i),
			hops:              1,
		}, deliver)
	}

	kept := frontier.labels[node]
	require.Len(t, kept, frontier.maxLabels)

	// The cheapest label survived, and it is still the cheapest.
	require.Contains(t, kept, cheapest)
	require.True(t, cheapest.active)

	for _, label := range kept {
		require.GreaterOrEqual(
			t, label.netAmountReceived,
			cheapest.netAmountReceived,
		)
	}
}
