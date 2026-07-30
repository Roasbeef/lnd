package routing

import (
	"testing"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// simIntervalGraph builds a graph the interval arm can actually route over,
// with enough degree that a payment has somewhere to learn.
func simIntervalGraph(t *testing.T) (*SimGraph, string) {
	t.Helper()

	graph, err := GenerateSimGraph(&SimTopologySpec{
		Type:           "smallworld",
		NumNodes:       40,
		ChannelSizeSat: 1_000_000,
		Seed:           42,
		AvgDegree:      6,
	})
	require.NoError(t, err)
	require.NoError(t, graph.AssignLiquidity(LiquidityUniform, 7))

	return graph, "1"
}

func simIntervalParams() *SimParams {
	params := DefaultSimParams()
	params.RouterImpl = IntervalPaymentRouter

	return params
}

// TestSimRouterImplKnob asserts the three things the params field promises: an
// absent or default value builds the stock session, "interval" builds the
// interval session, and an unknown name is refused rather than silently run as
// the stock stack.
func TestSimRouterImplKnob(t *testing.T) {
	t.Parallel()

	graph, srcRef := simIntervalGraph(t)
	source, err := graph.ResolveNode(srcRef)
	require.NoError(t, err)

	spec := &SimPaymentSpec{
		Target:       source,
		Amount:       50_000_000,
		MaxParts:     4,
		FeeLimitMsat: lnwire.MaxMilliSatoshi,
	}

	build := func(params *SimParams) (SimRouter, *SimRunner) {
		runner, err := NewSimRunner(graph, params, source, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(runner.Close)

		router, err := runner.routerFactory(
			&simGossipView{g: graph, now: runner.clk.Now}, source,
			graph.LocalBalances(source), spec,
		)
		require.NoError(t, err)

		return router, runner
	}

	// The stock stack: no belief store is built at all, and the session is
	// the one that has no ear on its own attempts.
	for _, name := range []string{"", DefaultPaymentRouter} {
		params := DefaultSimParams()
		params.RouterImpl = name

		router, runner := build(params)
		require.Nil(t, runner.intervalStore)

		stack, ok := router.(*lndStackRouter)
		require.True(t, ok)
		require.IsType(t, &paymentSession{}, stack.session)
		require.Nil(t, stack.reporter)
	}

	// The interval router: one store for the whole runner, and a session
	// that both reports to itself and can be told the payment is over.
	router, runner := build(simIntervalParams())
	require.NotNil(t, runner.intervalStore)

	stack, ok := router.(*lndStackRouter)
	require.True(t, ok)
	require.IsType(t, &intervalPaymentSession{}, stack.session)
	require.NotNil(t, stack.reporter)
	require.Implements(t, (*simRouterFinisher)(nil), router)

	// Mission control is still built and still handed to the arm, because
	// a node running the interval router for real still reports to it.
	require.NotNil(t, stack.mc)

	// Persistence is off: a simulator run has no database, and the store
	// has to be usable without one.
	require.NoError(t, runner.intervalStore.Start(t.Context()))
	require.Zero(t, runner.intervalStore.Len())

	// And an unknown name is an error, not a silent fallback.
	params := DefaultSimParams()
	params.RouterImpl = "nosuchrouter"
	_, err = NewSimRunner(graph, params, source, t.TempDir())
	require.ErrorContains(t, err, "unknown router_impl")
}

// TestSimIntervalStoreShared asserts that the belief store outlives the
// payment: what one payment learns is still there for the next one, which is
// the whole reason the store hangs off the runner rather than the router.
func TestSimIntervalStoreShared(t *testing.T) {
	t.Parallel()

	graph, srcRef := simIntervalGraph(t)
	source, err := graph.ResolveNode(srcRef)
	require.NoError(t, err)

	runner, err := NewSimRunner(
		graph, simIntervalParams(), source, t.TempDir(),
	)
	require.NoError(t, err)
	defer runner.Close()

	require.Zero(t, runner.intervalStore.Len())

	var attempts int
	for _, target := range []string{"10", "20", "30", "40"} {
		result, err := runner.RunScenario(&SimScenario{
			Target:   target,
			AmtMsat:  50_000_000,
			MaxParts: 4,
		})
		require.NoError(t, err)
		attempts += len(result.Attempts)
	}

	require.Greater(t, attempts, 0)

	// Every attempt is an observation, so a batch that sent anything has
	// to have left beliefs behind.
	require.Greater(t, runner.intervalStore.Len(), 0)

	// And nothing is still held: the batch is over, so every route the
	// sessions were handed has been either resolved or released. A leak
	// here would price the next payment's corridors against liquidity that
	// no htlc occupies.
	require.Zero(t, runner.intervalStore.HeldLen())
}

// TestSimIntervalReleaseOnGiveUp is the release seam on the path that has no
// report to hang it off: a payment that is impossible still asked for routes,
// and whatever those routes reserved has to come back.
func TestSimIntervalReleaseOnGiveUp(t *testing.T) {
	t.Parallel()

	graph, err := GenerateSimGraph(&SimTopologySpec{
		Type:           "line",
		NumNodes:       4,
		ChannelSizeSat: 100_000,
		Seed:           1,
		AvgDegree:      2,
	})
	require.NoError(t, err)
	require.NoError(t, graph.AssignLiquidity(LiquidityUniform, 3))

	source, err := graph.ResolveNode("1")
	require.NoError(t, err)

	runner, err := NewSimRunner(
		graph, simIntervalParams(), source, t.TempDir(),
	)
	require.NoError(t, err)
	defer runner.Close()

	// Far more than the line can carry, so the payment fails however it is
	// cut up.
	result, err := runner.RunScenario(&SimScenario{
		Target:   "4",
		AmtMsat:  10_000_000_000,
		MaxParts: 4,
	})
	require.NoError(t, err)
	require.False(t, result.Success)

	require.Zero(t, runner.intervalStore.HeldLen())
}
