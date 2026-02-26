package onionmessage

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btclog/v2"
	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/actor"
	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
)

// OnionMessageUpdate is an onion message update dispatched to any potential
// subscriber via the OnionMessageUpdateDispatcher.
type OnionMessageUpdate struct {
	// Peer is the peer pubkey.
	Peer [33]byte

	// PathKey is the route blinding ephemeral pubkey to be used for the
	// onion message.
	PathKey [33]byte

	// OnionBlob is the raw serialized mix header used to relay messages in
	// a privacy-preserving manner. This blob should be handled in the same
	// manner as onions used to route HTLCs, with the exception that it uses
	// blinded routes by default.
	OnionBlob []byte

	// CustomRecords contains any custom TLV records included in the
	// payload.
	CustomRecords record.CustomSet

	// ReplyPath contains the reply path information for the onion message.
	ReplyPath *sphinx.BlindedPath

	// EncryptedRecipientData contains the encrypted recipient data for the
	// onion message, created by the creator of the blinded route. This is
	// the receiver for the last leg of the route, and the sender for the
	// first leg up to the introduction point.
	EncryptedRecipientData []byte
}

// Request is a message sent to an Onion Peer Actor for processing. Each actor
// handles incoming onion messages from a specific peer, processing them through
// the sphinx router and either forwarding to the next hop or delivering
// locally.
type Request struct {
	// Embed BaseMessage to satisfy the actor package Message interface.
	actor.BaseMessage

	// Msg is the onion message received from the peer. This is exported so
	// the readHandler can construct requests directly.
	Msg lnwire.OnionMessage
}

// MessageType returns a string identifier for the Request message type.
func (m *Request) MessageType() string {
	return "OnionMessageRequest"
}

// Response is the response message sent back from an Onion Peer Actor.
type Response struct {
	actor.BaseMessage
	Success bool
}

// MessageType returns a string identifier for the Response message type.
func (m *Response) MessageType() string {
	return "OnionMessageResponse"
}

// OnionPeerActorRef is a reference to an Onion Peer Actor.
type OnionPeerActorRef actor.ActorRef[*Request, *Response]

// NewOnionMessageServiceKey creates a service key for registering and looking
// up onion peer actors. The service key uses the peer's compressed public key
// (hex-encoded) as the identifier. It returns both the service key and the
// hex-encoded public key string for use in actor naming and logging.
func NewOnionMessageServiceKey(
	pubKey [33]byte) (actor.ServiceKey[*Request, *Response], string) {

	pubKeyHex := hex.EncodeToString(pubKey[:])

	return actor.NewServiceKey[*Request, *Response](pubKeyHex), pubKeyHex
}

// OnionPeerActor handles incoming onion messages from a specific peer. It
// processes each message through the sphinx router, determines whether to
// forward it to the next hop or deliver it locally, and dispatches updates to
// RPC subscribers. This struct implements the actor.ActorBehavior interface and
// can be tested directly without the actor system.
type OnionPeerActor struct {
	// peerSender sends messages to peers by pubkey. This is backed by the
	// server's peer lookup, following the gossiper pattern.
	peerSender PeerMessageSender

	// router is the sphinx router for onion packet processing.
	router OnionRouter

	// resolver resolves SCIDs to node public keys.
	resolver NodeIDResolver

	// updateDispatcher dispatches updates to RPC subscribers.
	updateDispatcher OnionMessageUpdateDispatcher
}

// Receive processes an incoming onion message request. It decrypts the onion
// packet, determines the routing action (forward or deliver), executes it, and
// dispatches an update to any subscribers.
func (a *OnionPeerActor) Receive(ctx context.Context,
	req *Request) fn.Result[*Response] {

	select {
	case <-ctx.Done():
		log.DebugS(ctx, "OnionPeerActor context canceled, "+
			"not processing")

		return fn.Err[*Response](ErrActorShuttingDown)
	default:
	}

	onionMsg := &req.Msg

	logCtx := btclog.WithCtx(ctx,
		lnutils.LogPubKey("path_key", onionMsg.PathKey),
	)

	log.DebugS(logCtx, "OnionPeerActor processing onion message",
		btclog.HexN("onion_blob", onionMsg.OnionBlob, 10),
		slog.Int("blob_length", len(onionMsg.OnionBlob)),
	)

	// Process the onion message through the sphinx router.
	routingActionResult := processOnionMessage(
		a.router, a.resolver, onionMsg,
	)

	routingAction, err := routingActionResult.Unpack()
	if err != nil {
		log.ErrorS(logCtx, "Failed to process onion message", err)

		return fn.Err[*Response](fmt.Errorf("process onion "+
			"message: %w", err))
	}

	// Handle the routing action: forward or deliver.
	payload := fn.ElimEither(routingAction,
		func(fwd forwardAction) *lnwire.OnionMessagePayload {
			log.DebugS(logCtx, "Forwarding onion message",
				lnutils.LogPubKey(
					"next_node_id", fwd.nextNodeID,
				),
			)

			err := a.forwardMessage(
				fwd.nextNodeID, fwd.nextPathKey,
				fwd.nextPacket,
			)
			if err != nil {
				log.ErrorS(logCtx, "Failed to forward "+
					"onion message", err)
			}

			return fwd.payload
		},
		func(dlv deliverAction) *lnwire.OnionMessagePayload {
			log.DebugS(logCtx, "Delivering onion message "+
				"to self")

			return dlv.payload
		},
	)

	// Build the update for subscribers.
	var pathKeyArr [33]byte
	copy(
		pathKeyArr[:],
		onionMsg.PathKey.SerializeCompressed(),
	)

	update := &OnionMessageUpdate{
		PathKey:   pathKeyArr,
		OnionBlob: onionMsg.OnionBlob,
	}

	// If we have a payload, add its contents to the update.
	if payload != nil {
		customRecords := make(record.CustomSet)
		for _, v := range payload.FinalHopTLVs {
			customRecords[uint64(v.TLVType)] = v.Value
		}
		update.CustomRecords = customRecords
		update.ReplyPath = payload.ReplyPath
		update.EncryptedRecipientData = payload.EncryptedData
	}

	// Dispatch the update to any subscribers.
	if sendErr := a.updateDispatcher.SendUpdate(update); sendErr != nil {
		log.ErrorS(logCtx, "Failed to send onion message update",
			sendErr)

		return fn.Err[*Response](fmt.Errorf("send update: %w",
			sendErr))
	}

	return fn.Ok(&Response{Success: true})
}

// forwardMessage sends the onion message to the next node using the
// PeerMessageSender interface.
func (a *OnionPeerActor) forwardMessage(nextNodeID *btcec.PublicKey,
	nextBlindingPoint *btcec.PublicKey, nextPacket []byte) error {

	var nextNodeIDBytes [33]byte
	copy(nextNodeIDBytes[:], nextNodeID.SerializeCompressed())

	onionMsg := lnwire.NewOnionMessage(nextBlindingPoint, nextPacket)

	return a.peerSender.SendToPeer(nextNodeIDBytes, onionMsg)
}

// OnionActorFactory is a function type that creates and spawns an
// OnionPeerActor for a given peer within the actor system. All server-level
// dependencies are captured in the closure, so the caller only needs to provide
// the actor system and the peer's public key.
type OnionActorFactory func(
	system *actor.ActorSystem,
	pubKey [33]byte,
) (OnionPeerActorRef, error)

// NewOnionActorFactory creates a factory function that spawns OnionPeerActors
// with the given shared dependencies. The factory captures all server-level
// deps (sphinx router, resolver, peer sender, update dispatcher) in a closure
// so that each per-peer actor is created with identical configuration.
func NewOnionActorFactory(
	router OnionRouter,
	resolver NodeIDResolver,
	peerSender PeerMessageSender,
	updateDispatcher OnionMessageUpdateDispatcher,
) OnionActorFactory {

	return func(sys *actor.ActorSystem,
		pubKey [33]byte) (OnionPeerActorRef, error) {

		peerActor := &OnionPeerActor{
			peerSender:       peerSender,
			router:           router,
			resolver:         resolver,
			updateDispatcher: updateDispatcher,
		}

		serviceKey, pubKeyHex := NewOnionMessageServiceKey(pubKey)
		ref, err := serviceKey.Spawn(
			sys, "onion-peer-actor-"+pubKeyHex, peerActor,
		)
		if err != nil {
			return nil, err
		}

		log.Debugf("Spawned onion peer actor for peer %s",
			pubKeyHex)

		return ref, nil
	}
}

// findPeerActor looks up the onion peer actor for the given public key in the
// receptionist.
func findPeerActor(receptionist *actor.Receptionist, pubKey [33]byte,
) fn.Option[actor.ActorRef[*Request, *Response]] {

	serviceKey, _ := NewOnionMessageServiceKey(pubKey)
	refs := actor.FindInReceptionist(receptionist, serviceKey)

	return fn.Head(refs)
}

// StopPeerActor looks up the onion peer actor for the given public key and
// stops it. This should be called when a peer disconnects to clean up the
// actor. If no actor exists for the given public key, this is a no-op.
func StopPeerActor(system *actor.ActorSystem, pubKey [33]byte) {
	serviceKey, pubKeyHex := NewOnionMessageServiceKey(pubKey)

	actorOpt := findPeerActor(system.Receptionist(), pubKey)
	actorOpt.WhenSome(func(ref actor.ActorRef[*Request, *Response]) {
		log.Debugf("Stopping onion peer actor for peer %s", pubKeyHex)

		serviceKey.Unregister(system, ref)
	})
}
