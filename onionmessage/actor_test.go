package onionmessage

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningnetwork/lnd/actor"
	"errors"

	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
	"github.com/stretchr/testify/require"

	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/subscribe"
)

// mockPeerMessageSender is a mock PeerMessageSender that captures sent
// messages on a channel for test verification.
type mockPeerMessageSender struct {
	sent chan sentMessage
	err  error
}

// sentMessage captures a message sent via SendToPeer for test assertions.
type sentMessage struct {
	pubKey [33]byte
	msg    lnwire.Message
}

func newMockPeerMessageSender() *mockPeerMessageSender {
	return &mockPeerMessageSender{
		sent: make(chan sentMessage, 1),
	}
}

// SendToPeer implements PeerMessageSender.
func (m *mockPeerMessageSender) SendToPeer(pubKey [33]byte,
	msg lnwire.Message) error {

	if m.err != nil {
		return m.err
	}

	m.sent <- sentMessage{pubKey: pubKey, msg: msg}

	return nil
}

// mockUpdateDispatcher is a mock OnionMessageUpdateDispatcher that captures
// updates for test verification.
type mockUpdateDispatcher struct {
	updates chan any
	err     error
}

func newMockUpdateDispatcher() *mockUpdateDispatcher {
	return &mockUpdateDispatcher{
		updates: make(chan any, 1),
	}
}

// SendUpdate implements OnionMessageUpdateDispatcher.
func (m *mockUpdateDispatcher) SendUpdate(update any) error {
	if m.err != nil {
		return m.err
	}

	m.updates <- update

	return nil
}

// actorHarness wires up the minimal components required to test the
// OnionPeerActor's Receive method end-to-end.
type actorHarness struct {
	actor        *OnionPeerActor
	router       *sphinx.Router
	resolver     *mockNodeIDResolver
	peerSender   *mockPeerMessageSender
	dispatcher   *mockUpdateDispatcher
	actorSystem  *actor.ActorSystem
	nodeKey      *btcec.PrivateKey
}

func newActorHarness(t *testing.T) *actorHarness {
	t.Helper()

	nodeKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	router := sphinx.NewRouter(
		&sphinx.PrivKeyECDH{PrivKey: nodeKey},
		sphinx.NewMemoryReplayLog(),
	)
	require.NoError(t, router.Start())

	resolver := newMockNodeIDResolver()
	peerSender := newMockPeerMessageSender()
	dispatcher := newMockUpdateDispatcher()
	actorSystem := actor.NewActorSystem()

	peerActor := &OnionPeerActor{
		peerSender:       peerSender,
		router:           router,
		resolver:         resolver,
		updateDispatcher: dispatcher,
	}

	t.Cleanup(func() {
		router.Stop()
		_ = actorSystem.Shutdown()
	})

	return &actorHarness{
		actor:       peerActor,
		router:      router,
		resolver:    resolver,
		peerSender:  peerSender,
		dispatcher:  dispatcher,
		actorSystem: actorSystem,
		nodeKey:     nodeKey,
	}
}

// requireUpdate waits for an OnionMessageUpdate from the dispatcher.
func (h *actorHarness) requireUpdate(
	t *testing.T) *OnionMessageUpdate {

	t.Helper()

	select {
	case raw := <-h.dispatcher.updates:
		u, ok := raw.(*OnionMessageUpdate)
		require.True(t, ok, "unexpected update type")
		return u
	case <-time.After(time.Second):
		require.FailNow(t, "no update received")
		return nil
	}
}

// requireForwarded waits for a message sent via the PeerMessageSender.
func (h *actorHarness) requireForwarded(
	t *testing.T) sentMessage {

	t.Helper()

	select {
	case msg := <-h.peerSender.sent:
		return msg
	case <-time.After(time.Second):
		require.FailNow(t, "forwarded message not received")
		return sentMessage{}
	}
}

// requireNoForwarded verifies no message was forwarded.
func (h *actorHarness) requireNoForwarded(t *testing.T) {
	t.Helper()

	select {
	case <-h.peerSender.sent:
		require.FailNow(t, "unexpected forwarded message")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestOnionActorFactorySpawnsActor verifies the factory creates and registers
// an actor that can be found via the service key.
func TestOnionActorFactorySpawnsActor(t *testing.T) {
	t.Parallel()

	h := newActorHarness(t)

	factory := NewOnionActorFactory(
		h.router, h.resolver, h.peerSender, h.dispatcher,
	)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pubKeyArr := pubKeyToArray(privKey.PubKey())

	ref, err := factory(h.actorSystem, pubKeyArr)
	require.NoError(t, err)
	require.NotNil(t, ref)

	// Verify the actor is discoverable via the receptionist.
	actorOpt := findPeerActor(
		h.actorSystem.Receptionist(), pubKeyArr,
	)
	require.True(t, actorOpt.IsSome(), "actor should be found")
}

// TestStopPeerActor verifies that StopPeerActor correctly stops and removes
// an actor that was spawned via the factory.
func TestStopPeerActor(t *testing.T) {
	t.Parallel()

	h := newActorHarness(t)

	factory := NewOnionActorFactory(
		h.router, h.resolver, h.peerSender, h.dispatcher,
	)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pubKeyArr := pubKeyToArray(privKey.PubKey())

	_, err = factory(h.actorSystem, pubKeyArr)
	require.NoError(t, err)

	actorOpt := findPeerActor(
		h.actorSystem.Receptionist(), pubKeyArr,
	)
	require.True(t, actorOpt.IsSome(), "actor should exist")

	StopPeerActor(h.actorSystem, pubKeyArr)

	actorOpt = findPeerActor(
		h.actorSystem.Receptionist(), pubKeyArr,
	)
	require.True(t, actorOpt.IsNone(), "actor should be gone")
}

// TestStopPeerActorNotExists verifies that StopPeerActor is a no-op when no
// actor exists for the given pubkey.
func TestStopPeerActorNotExists(t *testing.T) {
	t.Parallel()

	system := actor.NewActorSystem()
	defer func() { _ = system.Shutdown() }()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pubKeyArr := pubKeyToArray(privKey.PubKey())

	// This should not panic or error - it's a no-op.
	StopPeerActor(system, pubKeyArr)
}

// TestFindPeerActorNotExists verifies that findPeerActor returns None when no
// actor has been spawned for the given pubkey.
func TestFindPeerActorNotExists(t *testing.T) {
	t.Parallel()

	system := actor.NewActorSystem()
	defer func() { _ = system.Shutdown() }()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pubKeyArr := pubKeyToArray(privKey.PubKey())

	actorOpt := findPeerActor(system.Receptionist(), pubKeyArr)
	require.True(t, actorOpt.IsNone(), "actor should not be found")
}

// TestOnionPeerActorReceiveContextCanceled tests that Receive returns an error
// when the context is canceled.
func TestOnionPeerActorReceiveContextCanceled(t *testing.T) {
	t.Parallel()

	h := newActorHarness(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	req := &Request{}

	result := h.actor.Receive(ctx, req)

	require.True(t, result.IsErr())
	result.WhenErr(func(err error) {
		require.ErrorIs(t, err, ErrActorShuttingDown)
	})
}

// hopBuildResult encapsulates the outputs of a hop building function.
type hopBuildResult struct {
	blindedPath *sphinx.BlindedPathInfo
	privKeys    []*btcec.PrivateKey
	after       func()
}

// buildHopsFunc is the signature for functions that construct test hop data.
type buildHopsFunc func(t *testing.T, h *actorHarness) hopBuildResult

// buildForwardNextNodeHops constructs hops for testing forward via next node.
func buildForwardNextNodeHops(
	t *testing.T, h *actorHarness) hopBuildResult {

	nextNodeKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	nextNodePub := nextNodeKey.PubKey()

	nextNode := fn.NewLeft[*btcec.PublicKey, lnwire.ShortChannelID](
		nextNodePub,
	)
	rdA := record.NewNonFinalBlindedRouteDataOnionMessage(
		nextNode, nil, nil,
	)
	rdB := &record.BlindedRouteData{}

	plainA := EncodeBlindedRouteData(t, rdA)
	plainB := EncodeBlindedRouteData(t, rdB)
	hops := []*sphinx.HopInfo{
		{NodePub: h.nodeKey.PubKey(), PlainText: plainA},
		{NodePub: nextNodePub, PlainText: plainB},
	}

	privKeys := []*btcec.PrivateKey{h.nodeKey, nextNodeKey}

	expectedPubKeyArr := pubKeyToArray(nextNodePub)
	after := func() {
		fwd := h.requireForwarded(t)
		require.Equal(t, expectedPubKeyArr, fwd.pubKey)
		require.NotNil(t, fwd.msg)
	}

	return hopBuildResult{
		blindedPath: BuildBlindedPath(t, hops),
		privKeys:    privKeys,
		after:       after,
	}
}

// buildForwardSCIDHops constructs hops for testing forward via SCID.
func buildForwardSCIDHops(
	t *testing.T, h *actorHarness) hopBuildResult {

	nextNodeKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	nextNodePub := nextNodeKey.PubKey()

	scid := lnwire.NewShortChanIDFromInt(555)
	h.resolver.addPeer(scid, nextNodePub)

	nextNode := fn.NewRight[*btcec.PublicKey](scid)
	rdA := record.NewNonFinalBlindedRouteDataOnionMessage(
		nextNode, nil, nil,
	)
	rdB := &record.BlindedRouteData{}

	plainA := EncodeBlindedRouteData(t, rdA)
	plainB := EncodeBlindedRouteData(t, rdB)
	hops := []*sphinx.HopInfo{
		{NodePub: h.nodeKey.PubKey(), PlainText: plainA},
		{NodePub: nextNodePub, PlainText: plainB},
	}

	privKeys := []*btcec.PrivateKey{h.nodeKey, nextNodeKey}

	expectedPubKeyArr := pubKeyToArray(nextNodePub)
	after := func() {
		fwd := h.requireForwarded(t)
		require.Equal(t, expectedPubKeyArr, fwd.pubKey)
		require.NotNil(t, fwd.msg)
	}

	return hopBuildResult{
		blindedPath: BuildBlindedPath(t, hops),
		privKeys:    privKeys,
		after:       after,
	}
}

// buildDeliverHops constructs hops for testing the deliver action (final hop).
func buildDeliverHops(t *testing.T, h *actorHarness) hopBuildResult {
	rd := &record.BlindedRouteData{}
	plain := EncodeBlindedRouteData(t, rd)
	hops := []*sphinx.HopInfo{
		{NodePub: h.nodeKey.PubKey(), PlainText: plain},
	}
	privKeys := []*btcec.PrivateKey{h.nodeKey}

	return hopBuildResult{
		blindedPath: BuildBlindedPath(t, hops),
		privKeys:    privKeys,
		after: func() {
			h.requireNoForwarded(t)
		},
	}
}

// buildForwardUnknownPeerHops constructs hops for testing forward to an
// unknown peer. The PeerMessageSender will return an error because the peer
// is not connected.
func buildForwardUnknownPeerHops(
	t *testing.T, h *actorHarness) hopBuildResult {

	nextNodeKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	nextNodePub := nextNodeKey.PubKey()

	nextNode := fn.NewLeft[*btcec.PublicKey, lnwire.ShortChannelID](
		nextNodePub,
	)
	rdA := record.NewNonFinalBlindedRouteDataOnionMessage(
		nextNode, nil, nil,
	)
	rdB := &record.BlindedRouteData{}

	hops := []*sphinx.HopInfo{
		{
			NodePub:   h.nodeKey.PubKey(),
			PlainText: EncodeBlindedRouteData(t, rdA),
		},
		{
			NodePub:   nextNodePub,
			PlainText: EncodeBlindedRouteData(t, rdB),
		},
	}

	privKeys := []*btcec.PrivateKey{h.nodeKey, nextNodeKey}

	// Make the sender return an error to simulate unknown peer.
	h.peerSender.err = errPeerNotConnected

	after := func() {
		h.requireNoForwarded(t)
	}

	return hopBuildResult{
		blindedPath: BuildBlindedPath(t, hops),
		privKeys:    privKeys,
		after:       after,
	}
}

// buildConcatenatedPathHops constructs a concatenated blinded path scenario
// where a sender's path is prepended to a receiver's blinded path, meeting at
// an introduction node with a NextBlindingOverride.
func buildConcatenatedPathHops(
	t *testing.T, h *actorHarness) hopBuildResult {

	introNodeKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	introNodePub := introNodeKey.PubKey()

	finalNodeKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	finalNodePub := finalNodeKey.PubKey()

	// Build the receiver's blinded path: introNode -> finalNode.
	nextNodeReceiver := fn.NewLeft[*btcec.PublicKey, lnwire.ShortChannelID](
		finalNodePub,
	)
	rdReceiverIntro := record.NewNonFinalBlindedRouteDataOnionMessage(
		nextNodeReceiver, nil, nil,
	)
	rdReceiverFinal := &record.BlindedRouteData{}

	receiverHops := []*sphinx.HopInfo{
		{
			NodePub: introNodePub,
			PlainText: EncodeBlindedRouteData(
				t, rdReceiverIntro,
			),
		},
		{
			NodePub: finalNodePub,
			PlainText: EncodeBlindedRouteData(
				t, rdReceiverFinal,
			),
		},
	}
	receiverPath := BuildBlindedPath(t, receiverHops)

	// Build the sender's path: firstHopNode -> introNode.
	nextNodeSender := fn.NewLeft[*btcec.PublicKey, lnwire.ShortChannelID](
		introNodePub,
	)
	blindingOverride := receiverPath.Path.BlindingPoint
	rdFirstHop := record.NewNonFinalBlindedRouteDataOnionMessage(
		nextNodeSender, blindingOverride, nil,
	)

	senderHops := []*sphinx.HopInfo{
		{
			NodePub: h.nodeKey.PubKey(),
			PlainText: EncodeBlindedRouteData(
				t, rdFirstHop,
			),
		},
	}
	senderPath := BuildBlindedPath(t, senderHops)

	concatenatedPath := ConcatBlindedPaths(t, senderPath, receiverPath)
	privKeys := []*btcec.PrivateKey{h.nodeKey, introNodeKey, finalNodeKey}

	expectedPathKey := blindingOverride
	expectedPubKeyArr := pubKeyToArray(introNodePub)
	after := func() {
		fwd := h.requireForwarded(t)
		require.Equal(t, expectedPubKeyArr, fwd.pubKey)

		onionMsg, ok := fwd.msg.(*lnwire.OnionMessage)
		require.True(t, ok)
		require.Equal(
			t, expectedPathKey, onionMsg.PathKey,
			"forwarded message should use override path key",
		)
	}

	return hopBuildResult{
		blindedPath: concatenatedPath,
		privKeys:    privKeys,
		after:       after,
	}
}

// TestOnionPeerActorRouting tests the OnionPeerActor's message processing
// across various routing scenarios including forwarding via next node ID,
// forwarding via SCID, delivery, concatenated paths, and unknown peer
// handling.
func TestOnionPeerActorRouting(t *testing.T) {
	t.Parallel()

	customTLVType := lnwire.InvoiceRequestNamespaceType + 1

	tests := []struct {
		name         string
		buildHops    buildHopsFunc
		finalHopTLVs []*lnwire.FinalHopTLV
	}{
		{
			name:      "forward next node",
			buildHops: buildForwardNextNodeHops,
		},
		{
			name:      "forward scid",
			buildHops: buildForwardSCIDHops,
		},
		{
			name:      "deliver",
			buildHops: buildDeliverHops,
			finalHopTLVs: []*lnwire.FinalHopTLV{
				{
					TLVType: customTLVType,
					Value:   []byte{1, 2, 3},
				},
			},
		},
		{
			name:      "forward concatenated path",
			buildHops: buildConcatenatedPathHops,
		},
		{
			name:      "forward unknown peer",
			buildHops: buildForwardUnknownPeerHops,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newActorHarness(t)

			result := tc.buildHops(t, h)
			onionMsg, cipherTexts := BuildOnionMessage(
				t, result.blindedPath, tc.finalHopTLVs,
			)

			ctx := t.Context()
			req := &Request{Msg: *onionMsg}

			// Call Receive directly on the actor.
			receiveResult := h.actor.Receive(ctx, req)

			// For unknown peer case, the actor still succeeds
			// (it processed the message and sent the update),
			// even though forwarding failed.
			if tc.name != "forward unknown peer" {
				require.True(
					t, receiveResult.IsOk(),
					"expected success",
				)
			}

			update := h.requireUpdate(t)
			require.Equal(
				t, onionMsg.OnionBlob, update.OnionBlob,
			)
			expectedData := cipherTexts[0]
			require.Equal(
				t, expectedData,
				update.EncryptedRecipientData,
			)

			// Peel the onion layers to verify correct
			// construction.
			peeled := PeelOnionLayers(
				t, result.privKeys, onionMsg,
			)
			require.Len(t, peeled, len(cipherTexts))
			for i := range peeled {
				require.Equal(
					t, cipherTexts[i],
					peeled[i].EncryptedData,
				)
			}

			for _, fht := range tc.finalHopTLVs {
				tlvType := fht.TLVType
				require.Equal(
					t, fht.Value,
					update.CustomRecords[uint64(tlvType)],
				)
			}

			result.after()
		})
	}
}

// TestOnionPeerActorInvalidOnionBlob verifies that processing fails gracefully
// when provided with an invalid onion blob that cannot be decoded.
func TestOnionPeerActorInvalidOnionBlob(t *testing.T) {
	t.Parallel()

	h := newActorHarness(t)

	onionMsg := &lnwire.OnionMessage{
		PathKey:   h.nodeKey.PubKey(),
		OnionBlob: []byte{1, 2, 3},
	}

	req := &Request{Msg: *onionMsg}

	result := h.actor.Receive(t.Context(), req)
	require.True(t, result.IsErr())

	// Verify no update was dispatched.
	select {
	case <-h.dispatcher.updates:
		require.FailNow(t, "unexpected update")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestOnionPeerActorSCIDResolutionFailure tests that forwarding via SCID fails
// gracefully when the SCID cannot be resolved to a node ID.
func TestOnionPeerActorSCIDResolutionFailure(t *testing.T) {
	t.Parallel()

	h := newActorHarness(t)

	nextNodeKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	nextNodePub := nextNodeKey.PubKey()

	// Use an SCID that is NOT registered in the resolver.
	unknownSCID := lnwire.NewShortChanIDFromInt(99999)

	nextNode := fn.NewRight[*btcec.PublicKey](unknownSCID)
	rdA := record.NewNonFinalBlindedRouteDataOnionMessage(
		nextNode, nil, nil,
	)
	rdB := &record.BlindedRouteData{}

	hops := []*sphinx.HopInfo{
		{
			NodePub:   h.nodeKey.PubKey(),
			PlainText: EncodeBlindedRouteData(t, rdA),
		},
		{
			NodePub:   nextNodePub,
			PlainText: EncodeBlindedRouteData(t, rdB),
		},
	}

	blindedPath := BuildBlindedPath(t, hops)
	onionMsg, _ := BuildOnionMessage(t, blindedPath, nil)

	req := &Request{Msg: *onionMsg}

	result := h.actor.Receive(t.Context(), req)
	require.True(t, result.IsErr())
}

// TestOnionPeerActorInvalidBlindedRouteData tests that invalid/malformed
// BlindedRouteData causes processing to fail gracefully.
func TestOnionPeerActorInvalidBlindedRouteData(t *testing.T) {
	t.Parallel()

	h := newActorHarness(t)

	hops := []*sphinx.HopInfo{
		{
			NodePub:   h.nodeKey.PubKey(),
			PlainText: []byte{0xFF, 0xFF, 0xFF, 0xFF},
		},
	}

	blindedPath := BuildBlindedPath(t, hops)
	onionMsg, _ := BuildOnionMessage(t, blindedPath, nil)

	req := &Request{Msg: *onionMsg}

	result := h.actor.Receive(t.Context(), req)
	require.True(t, result.IsErr())
}

// TestOnionPeerActorWithSubscribeServer tests the actor with a real
// subscribe.Server to verify end-to-end update dispatch.
func TestOnionPeerActorWithSubscribeServer(t *testing.T) {
	t.Parallel()

	nodeKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	router := sphinx.NewRouter(
		&sphinx.PrivKeyECDH{PrivKey: nodeKey},
		sphinx.NewMemoryReplayLog(),
	)
	require.NoError(t, router.Start())
	t.Cleanup(router.Stop)

	server := subscribe.NewServer()
	require.NoError(t, server.Start())
	t.Cleanup(func() { _ = server.Stop() })

	client, err := server.Subscribe()
	require.NoError(t, err)
	t.Cleanup(client.Cancel)

	peerActor := &OnionPeerActor{
		peerSender:       newMockPeerMessageSender(),
		router:           router,
		resolver:         newMockNodeIDResolver(),
		updateDispatcher: server,
	}

	// Build a single-hop deliver path.
	rd := &record.BlindedRouteData{}
	plain := EncodeBlindedRouteData(t, rd)
	hops := []*sphinx.HopInfo{
		{NodePub: nodeKey.PubKey(), PlainText: plain},
	}

	blindedPath := BuildBlindedPath(t, hops)
	onionMsg, _ := BuildOnionMessage(t, blindedPath, nil)

	req := &Request{Msg: *onionMsg}
	result := peerActor.Receive(t.Context(), req)
	require.True(t, result.IsOk())

	// Verify update via real subscribe.Server.
	select {
	case raw := <-client.Updates():
		u, ok := raw.(*OnionMessageUpdate)
		require.True(t, ok)
		require.Equal(t, onionMsg.OnionBlob, u.OnionBlob)
	case <-time.After(time.Second):
		require.FailNow(t, "no update received from subscribe server")
	}
}

// pubKeyToArray converts a public key to a [33]byte array.
func pubKeyToArray(pk *btcec.PublicKey) [33]byte {
	var out [33]byte
	copy(out[:], pk.SerializeCompressed())
	return out
}

// errPeerNotConnected is used in tests to simulate an unknown peer.
var errPeerNotConnected = errors.New("peer not connected")
