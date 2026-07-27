package routerrpc

import (
	"testing"

	"github.com/lightningnetwork/lnd/routing"
	"github.com/stretchr/testify/require"
)

// TestDefaultRouter tests that the payment router defaults to lnd's production
// stack, so that a node which says nothing about routing keeps the behaviour it
// had before the interval router existed.
func TestDefaultRouter(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	require.Equal(t, routing.DefaultPaymentRouter, cfg.PaymentRouter)

	// The selection survives the trip through GetRoutingConfig, which is
	// what the server actually reads.
	require.Equal(
		t, routing.DefaultPaymentRouter,
		GetRoutingConfig(cfg).PaymentRouter,
	)

	cfg.PaymentRouter = routing.IntervalPaymentRouter
	require.Equal(
		t, routing.IntervalPaymentRouter,
		GetRoutingConfig(cfg).PaymentRouter,
	)
}
