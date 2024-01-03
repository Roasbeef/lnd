package chancloser

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/labels"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/protofsm"
	"github.com/lightningnetwork/lnd/tlv"
)

// TODO(roasbeef): func to map an incoming wire message to a stage transition

// sendShutdownEvents is a helper function that returns a set of daemon events
// we need to emit when we decide that we should send a shutdown message.
func sendShutdownEvents(chanID lnwire.ChannelID, chanPoint wire.OutPoint,
	deliveryAddr lnwire.DeliveryAddress, peerPub btcec.PublicKey,
	postSendEvent fn.Option[ProtocolEvent]) protofsm.DaemonEventSet {

	// Before closing, we'll attempt to send a disable update for the
	// channel.  We do so before closing the channel as otherwise the
	// current edge policy won't be retrievable from the graph.  This'll be
	// another external event.
	disableEvent := &protofsm.DisableChannelEvent{
		ChanPoint: chanPoint,
	}

	// We'll emit a daemon event that instructs the daemon to send out a
	// new shutdown message to the remote peer.
	msgsToSend := &protofsm.SendMsgEvent[ProtocolEvent]{
		TargetPeer: peerPub,
		Msgs: []lnwire.Message{&lnwire.Shutdown{
			ChannelID: chanID,
		}},
		SendWhen: fn.Some(func() bool {
			// TODO(roasbeef): poll env once all flushed out
			return true
		}),
		PostSendEvent: postSendEvent,
	}

	return protofsm.DaemonEventSet{disableEvent, msgsToSend}
}

// validateShutdown is a helper function that validates that the shutdown has a
// proper delivery script, and can be sent based on the current thaw height of
// the channel.
func validateShutdown(chanThawHeight fn.Option[uint32],
	upfrontAddr fn.Option[lnwire.DeliveryAddress],
	msg *ShutdownReceived, chanPoint wire.OutPoint,
	chainParams chaincfg.Params) error {

	// If we've received a shutdown message, and we have a thaw height,
	// then we need to make sure that the channel can now be co-op closed.
	err := fn.MapOption(func(thawHeight uint32) error {
		// If the current height is below the thaw height, then we'll
		// reject the shutdown message as we can't yet co-op close the
		// channel.
		if msg.BlockHeight < thawHeight {
			return fmt.Errorf("initiator attempting to "+
				"co-op close frozen ChannelPoint(%v) "+
				"(current_height=%v, thaw_height=%v)",
				chanPoint, msg.BlockHeight,
				thawHeight)
		}

		return nil
	})(chanThawHeight).UnwrapOr(nil)
	if err != nil {
		return err
	}

	// Next, we'll verify that the remote party is sending the expected
	// shutdown script.
	return fn.MapOption(func(addr lnwire.DeliveryAddress) error {
		return validateShutdownScript(
			addr, msg.ShutdownScript, &chainParams,
		)
	})(upfrontAddr).UnwrapOr(nil)
}

// ProcessEvent takes a protocol event, and implements a state transition for
// the state. From this state, we can receive two possible incoming events:
// SendShutdown and ShutdownReceived. Both of these will transition us to the
// ChannelFlushing state.
func (c *ChannelActive) ProcessEvent(event ProtocolEvent, env *Environment,
) (*CloseStateTransition, error) {

	// TODO(roasbeef): also need to handle the conf event at any of these
	// states?
	//  * can implement as a wrapper state for all of them? ConfTerminal[T]

	switch msg := event.(type) {

	// If we get a confirmation, then a prior transaction we broadcasted
	// has confirmed, so we can move to our terminal state early.
	//
	// TODO(roasbeef): implement as ConfWrapper[T]?
	case *ConfEvent:
		// TODO(roasbeef): can't actually use due to interface there???
		// TODO(roasbeef): any other clean up events needed?
		return &CloseStateTransition{
			NextState: &CloseFin{
				transitionEvent: msg,
			},
		}, nil

	// If we receive the SendShutdown event, then we'll send our shutdown
	// with a special SendPredicate, then go to the ShutdownPending where
	// we'll wait for the remote to send their shutdown.
	case *SendShutdown:
		// If we have an upfront shutdown addr or a delivery addr then
		// we'll use that. Otherwise, we'll generate a new delivery
		// addr.
		shutdownScript, err := env.LocalUpfrontShutdown.Alt(
			msg.DeliveryAddr,
		).UnwrapOrFuncErr(env.NewDeliveryScript)
		if err != nil {
			return nil, err
		}

		// We'll emit some daemon events to send the shutdown message
		// and disable the channel on the network level. In this case,
		// we don't need a post send event as receive their shutdown is
		// what'll move us beyond the ShutdownPending state.
		daemonEvents := sendShutdownEvents(
			env.ChanID, env.ChanPoint, shutdownScript,
			env.ChanPeer, fn.None[ProtocolEvent](),
		)

		// We'll also record that we arrived at the ShutdownPending
		// state via a SendShutdown event, which means this was a
		// locally initiated shutdown.
		shutdownTransition := fn.NewLeft[
			SendShutdown, ShutdownReceived,
		](*msg)

		// From here, we'll transition to the closing flushing state.
		// In this state we await their shutdown message (self loop),
		// then also the flushing event.
		return &CloseStateTransition{
			NextState: &ShutdownPending{
				prevState:   c,
				inputEvents: shutdownTransition,
				ShutdownScripts: ShutdownScripts{
					LocalDeliveryScript: shutdownScript,
				},
			},
			// TODO(roasbeef): type alias
			NewEvents: fn.Some(protofsm.EmittedEvent[ProtocolEvent]{
				ExternalEvents: fn.Some(daemonEvents),
			}),
		}, nil

	// When we receive a shutdown from the remote party, we'll validate the
	// shutdown message, then transition to the ChannelFlushing state.
	// We'll also emit similar events like the above to send out shutdown,
	// and also disable the channel.
	case *ShutdownReceived:
		// Validate that they can send the message now, and also that
		// they haven't violated their commitment to a prior upfront
		// shutdown addr.
		err := validateShutdown(
			env.ThawHeight, env.RemoteUpfrontShutdown, msg,
			env.ChanPoint, env.ChainParams,
		)
		if err != nil {
			return nil, err
		}

		// If we have an upfront shutdown addr we'll use that,
		// otherwise, we'll generate a new delivery script.
		shutdownAddr, err := env.LocalUpfrontShutdown.UnwrapOrFuncErr(
			env.NewDeliveryScript,
		)
		if err != nil {
			return nil, err
		}

		// Now that we know the shutdown message is valid, we'll obtain
		// the set of daemon events we need to emit. We'll also specify
		// that once the message has actually been sent, that we
		// generate receive an input event of a ShutdownComplete.
		daemonEvents := sendShutdownEvents(
			env.ChanID, env.ChanPoint, shutdownAddr,
			env.ChanPeer,
			fn.Some[ProtocolEvent](&ShutdownComplete{}),
		)

		// We'll also record that we arrived at the ChannelFlushing
		// state via a ShutdownReceived event, which means this was a
		// locally initiated shutdown.
		shutdownTransition := fn.NewRight[SendShutdown](*msg)

		return &CloseStateTransition{
			NextState: &ShutdownPending{
				prevState:   c,
				inputEvents: shutdownTransition,
				ShutdownScripts: ShutdownScripts{
					LocalDeliveryScript:  shutdownAddr,
					RemoteDeliveryScript: msg.ShutdownScript,
				},
			},
			NewEvents: fn.Some(protofsm.EmittedEvent[ProtocolEvent]{
				ExternalEvents: fn.Some(daemonEvents),
			}),
		}, nil

	// Any other messages in this state will result in an error, as this is
	// an undefined state transition.
	default:
		return nil, fmt.Errorf("%w: received %T while in ChannelActive",
			ErrInvalidStateTransition, msg)
	}
}

// ProcessEvent takes a protocol event, and implements a state transition for
// the state. Our path to this state will determine the set of valid events. If
// we were the one that sent the shutdown, then we'lljust wait on the
// ShutdownReceived event. Otherwise, we received the shutdown, and can move
// forward once we recieve the ShutdownComplete event. Receiving
// ShutdownComplete means that we've sent our shutdown, as this was specified
// as a post send event.
func (s *ShutdownPending) ProcessEvent(event ProtocolEvent, env *Environment,
) (*CloseStateTransition, error) {

	switch msg := event.(type) {

	// If we get a confirmation, then a prior transaction we broadcasted
	// has confirmed, so we can move to our terminal state early.
	//
	// TODO(roasbeef): implement as ConfWrapper[T]?
	case *ConfEvent:
		// TODO(roasbeef): any other clean up events needed?
		return &CloseStateTransition{
			NextState: &CloseFin{
				transitionEvent: msg,
			},
		}, nil

	// When we receive a shutdown from the remote party, we'll validate the
	// shutdown message, then transition to the ChannelFlushing state.
	case *ShutdownReceived:
		// Validate that they can send the message now, and also that
		// they haven't violated their commitment to a prior upfront
		// shutdown addr.
		err := validateShutdown(
			env.ThawHeight, env.RemoteUpfrontShutdown, msg,
			env.ChanPoint, env.ChainParams,
		)
		if err != nil {
			return nil, err
		}

		// We'll also record that we arrived at the ChannelFlushing
		// state via a ShutdownReceived event, which means this was a
		// locally initiated shutdown.
		shutdownTransition := fn.NewRight[ShutdownComplete](*msg)

		// If we have an upfront shutdown addr we'll use that,
		// otherwise, we'll generate a new delivery script.
		shutdownAddr, err := env.LocalUpfrontShutdown.UnwrapOrFuncErr(
			env.NewDeliveryScript,
		)
		if err != nil {
			return nil, err
		}

		// We transition to the ChannelFlushing state, where we await
		// the ChannelFlushed event.
		return &CloseStateTransition{
			NextState: &ChannelFlushing{
				inputEvents: shutdownTransition,
				prevState:   s,
				ShutdownScripts: ShutdownScripts{
					LocalDeliveryScript:  shutdownAddr,
					RemoteDeliveryScript: msg.ShutdownScript,
				},
			},
		}, nil

	// If we get this message, then this means that we were finally able to
	// send out shutdown after receiving it from the remote party. We'll
	// now transition directly to the ChannelFlushing state.
	case *ShutdownComplete:
		// We'll also record that we arrived at the ChannelFlushing
		// state via a ShutdownComplete event, which means this was a
		// locally initiated shutdown.
		shutdownTransition := fn.NewLeft[
			ShutdownComplete, ShutdownReceived,
		](*msg)

		// From here, we'll transition to the channel flushing state.
		// We'll stay here until we receive the ChannelFlushed event.
		return &CloseStateTransition{
			NextState: &ChannelFlushing{
				prevState:       s,
				inputEvents:     shutdownTransition,
				ShutdownScripts: s.ShutdownScripts,
			},
		}, nil

	// Any other messages in this state will result in an error, as this is
	// an undefined state transition.
	default:
		return nil, fmt.Errorf("%w: received %T while in ShutdownPending",
			ErrInvalidStateTransition, msg)
	}
}

// ProcessEvent takes a new protocol event, and figures out if we can
// transition to the next state, or just loop back upon ourself. If we receive
// a ShutdownReceived event, then we'll stay in the ChannelFlushing state, as
// we haven't yet fully cleared the channel. Otherwise, we can move to the
// CloseReady state which'll being the channel closing process.
func (c *ChannelFlushing) ProcessEvent(event ProtocolEvent, env *Environment,
) (*CloseStateTransition, error) {

	switch msg := event.(type) {

	// If we get a confirmation, then a prior transaction we broadcasted
	// has confirmed, so we can move to our terminal state early.
	case *ConfEvent:
		// TODO(roasbeef): any other clean up events needed?
		return &CloseStateTransition{
			NextState: &CloseFin{
				transitionEvent: msg,
			},
		}, nil

	// If we receive the ChannelFlushed event, then the coast is clear so
	// we'll now morph into the dual peer state so we can handle any
	// messages needed to drive forward the close process.
	case *ChannelFlushed:
		// Both the local and remote losing negotiation needs the terms
		// we'll be using to close the channel, so we'll create them
		// here.
		closeTerms := CloseChannelTerms{
			ShutdownScripts:  c.prevState.ShutdownScripts,
			ShutdownBalances: msg.ShutdownBalances,
		}

		// Each time we go into this negotiation flow, we'll kick off
		// our local state with a new close attempt. So we'll emit a
		// internal event to drive forward that part of the state.
		localOfferSign := ProtocolEvent(&SendOfferEvent{
			// TODO(roasbeef): add fee rate
			//targetFeeRate: c.prevState.targetFeeRate,
		})

		// TODO(roasbeef): don't send localOfferSign if we can't pay
		// for the fees

		// TODO(roasbeef): event to watch for spend conf?

		// At this point, we may end up broadcasting a commitment

		return &CloseStateTransition{
			NextState: &ClosingNegotiation{
				peerState: DualPeerState{
					localState: &LocalCloseStart{
						CloseChannelTerms: closeTerms,
					},
					remoteState: &RemoteCloseStart{
						CloseChannelTerms: closeTerms,
					},
				},
			},
			NewEvents: fn.Some(protofsm.EmittedEvent[ProtocolEvent]{
				InternalEvent: fn.Some(localOfferSign),
			}),
		}, nil

	default:
		return nil, fmt.Errorf("%w: received %T while in ChannelFlushing",
			ErrInvalidStateTransition, msg)
	}
}

// ProcessEvent drives forward the composite states for the local and remote
// party in response to new events. From this state, we'll continue to drive
// forward the local and remote states until we arrive at the StateFin stage,
// or we loop back up to the ShutdownPending state.
func (c *ClosingNegotiation) ProcessEvent(event ProtocolEvent, env *Environment,
) (*CloseStateTransition, error) {

	// There're two classes of events that can break us out of this state:
	// we receive a confirmation event, or we receive a signal to restart
	// the co-op close process.
	switch msg := event.(type) {
	// If we get a confirmation, then the spend request we issued when we
	// were leaving the ChannelFlushing state has been confirmed.  We'll
	// now transition to the StateFin state.
	case *ConfEvent:
		// TODO(roasbeef): any other clean up events needed?
		return &CloseStateTransition{
			NextState: &CloseFin{
				transitionEvent: msg,
			},
		}, nil

	// Otherwise, if we receive a shutdown, or receive an event to send a
	// shutdown, then we'll go back up to the ChannelActive state, and have
	// it handle this event by emitting an internal event.
	case *ShutdownReceived, *SendShutdown:
		return &CloseStateTransition{
			NextState: &ChannelActive{},
			NewEvents: fn.Some(protofsm.EmittedEvent[ProtocolEvent]{
				InternalEvent: fn.Some(event),
			}),
		}, nil
	}

	// If we get to this point, then we have an event that'll drive forward
	// the negotiation process.  Based on the event, we'll figure out which
	// state we'll be modifying.
	switch {
	case c.peerState.localState.ShouldRouteTo(event):
		// Drive forward the local state based on the next event.
		transition, err := c.peerState.localState.ProcessEvent(
			event, env,
		)
		if err != nil {
			return nil, err
		}

		nextLocalState, ok := transition.NextState.(AsymmetricPeerState)
		if !ok {
			return nil, fmt.Errorf("expected %T to be "+
				"AsymmetricPeerState", transition.NextState)
		}

		return &CloseStateTransition{
			NextState: &ClosingNegotiation{
				peerState: DualPeerState{
					localState:  nextLocalState,
					remoteState: c.peerState.remoteState,
				},
			},
			NewEvents: transition.NewEvents,
		}, nil

	case c.peerState.remoteState.ShouldRouteTo(event):
		// Drive forward the remote state based on the next event.
		transition, err := c.peerState.remoteState.ProcessEvent(
			event, env,
		)
		if err != nil {
			return nil, err
		}

		nextRemoteState, ok := transition.NextState.(AsymmetricPeerState)
		if !ok {
			return nil, fmt.Errorf("expected %T to be "+
				"AsymmetricPeerState", transition.NextState)
		}

		return &CloseStateTransition{
			NextState: &ClosingNegotiation{
				peerState: DualPeerState{
					localState:  c.peerState.localState,
					remoteState: nextRemoteState,
				},
			},
			NewEvents: transition.NewEvents,
		}, nil
	}

	return nil, fmt.Errorf("%w: received %T while in ClosingNegotiation",
		ErrInvalidStateTransition, event)
}

// newSigTlv is a helper function that returns a new optional TLV sig field for
// the parametrized tlv.TlvType value.
func newSigTlv[T tlv.TlvType](s lnwire.Sig) tlv.OptionalRecordT[T, lnwire.Sig] {
	return tlv.OptionalRecordT[T, lnwire.Sig]{
		Option: fn.Some(tlv.NewRecordT[T](
			s,
		)),
	}
}

// ProcessEvent implements the event processing to kick off the process of
// obtaining a new (possibly RBF'd) signature for our commitment transaction.
func (l *LocalCloseStart) ProcessEvent(event ProtocolEvent, env *Environment,
) (*CloseStateTransition, error) {

	switch msg := event.(type) {
	// If we receive a SendOfferEvent, then we'll use the specified fee
	// rate to generate for the closing transaction with our ideal fee
	// rate.
	case *SendOfferEvent:
		feeRate := msg.targetFeeRate

		localTxOut, remoteTxOut := l.CloseChannelTerms.DeriveCloseTxOuts()

		// First, we'll use our target fee rate, and the local+remote
		// outputs to determine what the absolute fee we'll pay is.
		//
		// TODO(roasbeef): need to sign the 3 diff versions of this?
		absoluteFee := env.FeeEstimator.EstimateFee(
			env.ChanType, localTxOut, remoteTxOut,
			feeRate.FeePerKWeight(),
		)

		// TODO(roasbeef): if remove dust, need to set CloserNoClosee

		// Now that we know what fee we want to pay, we'll create a new
		// signature over our co-op close transaction.
		localScript := l.CloseChannelTerms.LocalDeliveryScript
		rawSig, _, closeBalance, err := env.CloseSigner.CreateCloseProposal(
			absoluteFee, localScript,
			l.CloseChannelTerms.RemoteDeliveryScript,
		)
		if err != nil {
			return nil, err
		}
		wireSig, err := lnwire.NewSigFromSignature(rawSig)
		if err != nil {
			return nil, err
		}

		// Now that we have our signature, we'll set the proper
		// closingSigs field based on if the remote party's output is
		// dust or not.
		var closingSigs lnwire.ClosingSigs
		switch {
		// If the remote party's output is dust, then we'll set the
		// CloserNoClosee field.
		case remoteTxOut == nil:
			closingSigs.CloserNoClosee = newSigTlv[*tlv.TlvType1](wireSig)

		// If after paying for fees, our balance is below dust, then
		// we'll set the NoCloserClosee field.
		case closeBalance < lnwallet.DustLimitForSize(len(localScript)):
			closingSigs.NoCloserClosee = newSigTlv[*tlv.TlvType2](wireSig)

		// Otherwise, we'll set the CloserAndClosee field.
		//
		// TODO(roasbeef): should actually set both??
		default:
			closingSigs.CloserAndClosee = newSigTlv[*tlv.TlvType3](wireSig)
		}

		// TODO(roasbeef): sequence just needs to be non max?
		//  * also need to verify that

		// Now that we have our sig, we'll emit a daemon event to send
		// it to the remote party, then transition to the
		// LocalOfferSent state.
		//
		// TODO(roasbeef): type alias for protocol event
		sendEvent := protofsm.DaemonEventSet{&protofsm.SendMsgEvent[ProtocolEvent]{
			TargetPeer: env.ChanPeer,
			// TODO(roasbeef): mew new func
			Msgs: []lnwire.Message{&lnwire.ClosingComplete{
				ChannelID:   env.ChanID,
				FeeSatoshis: absoluteFee,
				Sequence:    mempool.MaxRBFSequence,
				ClosingSigs: closingSigs,
			}},
		}}

		return &CloseStateTransition{
			NextState: &LocalOfferSent{
				prevState:         l,
				transitionEvent:   msg,
				ProposedFee:       absoluteFee,
				LocalSig:          wireSig,
				CloseChannelTerms: l.CloseChannelTerms,
			},
			NewEvents: fn.Some(protofsm.EmittedEvent[ProtocolEvent]{
				ExternalEvents: fn.Some(sendEvent),
			}),
		}, nil
	}

	return nil, fmt.Errorf("%w: received %T while in LocalCloseStart",
		ErrInvalidStateTransition, event)
}

// extractSig...
func extractSig(msg lnwire.ClosingSig) (*lnwire.Sig, error) {
	// First, we'll validate that only one signature is included in their
	// response to our initial offer. If not, then we'll exit here, and
	// trigger a recycle of the connection.
	sigBools := []bool{
		msg.CloserNoClosee.IsSome(), msg.NoCloserClosee.IsSome(),
		msg.CloserAndClosee.IsSome(),
	}
	numSigs := fn.Reduce(sigBools, func(acc int, b bool) int {
		if b {
			return acc + 1
		}

		return acc
	})
	if numSigs != 1 {
		// TODO(roasbeef): better error
		return nil, fmt.Errorf("received multiple signatures, "+
			"expected: 1, got: %v", numSigs)
	}

	// TODO(roasbeef): better way to write?

	var sig *lnwire.Sig
	msg.CloserNoClosee.WhenSomeV(func(s lnwire.Sig) {
		sig = &s
	})
	msg.NoCloserClosee.WhenSomeV(func(s lnwire.Sig) {
		sig = &s
	})
	msg.CloserAndClosee.WhenSomeV(func(s lnwire.Sig) {
		sig = &s
	})

	return sig, nil
}

// ProcessEvent implements the state transition function for the
// LocalOfferSent state. In this state, we'll wait for the remote party to
// send a close_signed message which gives us the ability to broadcast a new
// co-op close transaction.
func (l *LocalOfferSent) ProcessEvent(event ProtocolEvent, env *Environment,
) (*CloseStateTransition, error) {

	switch msg := event.(type) {
	// If we receive a LocalSigReceived event, then we'll attempt to
	// validate the signature from the remote party. If valid, then we can
	// broadcast the transaction, and transition to the ClosePending state.
	case *LocalSigReceived:
		// Extract and validate that only one sig field is set.
		sig, err := extractSig(msg.SigMsg)
		if err != nil {
			return nil, err
		}

		remoteSig, err := sig.ToSignature()
		if err != nil {
			return nil, err
		}
		localSig, err := l.LocalSig.ToSignature()
		if err != nil {
			return nil, err
		}

		// Now that we have their signature, we'll attempt to validate
		// it, then extract a valid closing signature from it.
		closeTx, _, err := env.CloseSigner.CompleteCooperativeClose(
			localSig, remoteSig,
			l.CloseChannelTerms.LocalDeliveryScript,
			l.CloseChannelTerms.RemoteDeliveryScript,
			l.ProposedFee,
		)
		if err != nil {
			return nil, err
		}

		broadcastEvent := protofsm.DaemonEventSet{&protofsm.BroadcastTxn{
			Tx: closeTx,
			Label: labels.MakeLabel(
				labels.LabelTypeChannelClose, &env.Scid,
			),
		}}

		transitionEvent := fn.NewLeft[LocalSigReceived, OfferReceivedEvent](*msg)

		// TODO(roasbeef): mark broadcast? or have as pre broadcast event?
		//err = c.cfg.Channel.MarkCoopBroadcasted(

		return &CloseStateTransition{
			NextState: &ClosePending{
				transitionEvents: transitionEvent,
			},
			NewEvents: fn.Some(protofsm.EmittedEvent[ProtocolEvent]{
				ExternalEvents: fn.Some(broadcastEvent),
			}),
		}, nil

	}

	return nil, fmt.Errorf("%w: received %T while in LocalOfferSent",
		ErrInvalidStateTransition, event)
}

// ProcessEvent implements the state transition function for the
// RemoteCloseStart. In this state, we'll wait for the remote party to send a
// closing_complete message. Assuming they can pay for the fees, we'll sign it
// ourselves, then transition to the next state of RemoteOfferReceived.
func (l *RemoteCloseStart) ProcessEvent(event ProtocolEvent, env *Environment,
) (*CloseStateTransition, error) {

	switch msg := event.(type) {
	// If we receive a OfferReceived event, we'll make sure they can
	// actually pay for the fee. If so, then we'll counter sign and
	// transition to a terminal state.
	case *OfferReceivedEvent:
		// To start, we'll perform some basic validation of the sig
		// message they've sent.
		switch {
		// We'll validate that the remote party actually has enough
		// fees to pay the closing fees.
		case msg.SigMsg.FeeSatoshis > l.RemoteBalance.ToSatoshis():
			return nil, fmt.Errorf("remote party can't afford "+
				"fees: %v vs %v", msg.SigMsg.FeeSatoshis,
				l.RemoteBalance.ToSatoshis())

		// The sequence they send can't be the max sequence, as that
		// would prevent RBF.
		//
		// TODO(roasbeef): add ability to pass sequence into
		// sign/verify
		case msg.SigMsg.Sequence == wire.MaxTxInSequenceNum:
			return nil, fmt.Errorf("remote party sent max sequence "+
				"number: %v", msg.SigMsg.Sequence)
		}

		// With the basic sanity checks out of the way, we'll now
		// figure out which signature that we'll attempt to sign
		// against.
		var (
			remoteSig input.Signature
			noClosee  bool
		)
		switch {
		// If our balance is dust, then we expect the CloserNoClosee
		// sig to be set.
		case l.LocalAmtIsDust():
			if msg.SigMsg.CloserNoClosee.IsNone() {
				return nil, fmt.Errorf("expected CloserNoClosee " +
					"sig to be set")
			}
			msg.SigMsg.CloserNoClosee.WhenSomeV(func(s lnwire.Sig) {
				remoteSig, _ = s.ToSignature()
				noClosee = true
			})

		// Otherwise, we'll assume that CloseAndClosee is set.
		//
		// TODO(roasbeef): NoCloserClosee, but makes no sense?
		default:
			if msg.SigMsg.CloserAndClosee.IsNone() {
				return nil, fmt.Errorf("expected " +
					"CloserAndClosee sig to be set")
			}
			msg.SigMsg.CloserAndClosee.WhenSomeV(func(s lnwire.Sig) {
				remoteSig, _ = s.ToSignature()
			})
		}

		// Now that we have the remote sig, we'll sign the version they
		// signed, then attempt to complete the cooperative close
		// process.
		//
		// TODO(roasbeef): need to be able to omit an output when
		// signing based on the above, as closing opt
		rawSig, _, _, err := env.CloseSigner.CreateCloseProposal(
			msg.SigMsg.FeeSatoshis,
			l.CloseChannelTerms.LocalDeliveryScript,
			l.CloseChannelTerms.RemoteDeliveryScript,
		)
		if err != nil {
			return nil, err
		}
		wireSig, err := lnwire.NewSigFromSignature(rawSig)
		if err != nil {
			return nil, err
		}

		localSig, err := wireSig.ToSignature()
		if err != nil {
			return nil, err
		}

		// With our signature created, we'll now attempt to finalize
		// the close process.
		//
		// TODO(roasbef); duplication
		closeTx, _, err := env.CloseSigner.CompleteCooperativeClose(
			localSig, remoteSig,
			l.CloseChannelTerms.LocalDeliveryScript,
			l.CloseChannelTerms.RemoteDeliveryScript,
			msg.SigMsg.FeeSatoshis,
		)
		if err != nil {
			return nil, err
		}

		var closingSigs lnwire.ClosingSigs
		if noClosee {
			closingSigs.CloserNoClosee = newSigTlv[*tlv.TlvType1](wireSig)
		} else {
			closingSigs.CloserAndClosee = newSigTlv[*tlv.TlvType3](wireSig)
		}

		// As we transition, we'll omit two events: one to broadcast
		// the transaction, and the other to send our ClosingSig
		// message to the remote party.
		//
		// TODO(roasbeef): mark on disk again after send?
		sendEvent := &protofsm.SendMsgEvent[ProtocolEvent]{
			TargetPeer: env.ChanPeer,
			Msgs: []lnwire.Message{&lnwire.ClosingSig{
				ChannelID:   env.ChanID,
				ClosingSigs: closingSigs,
			}},
		}
		broadcastEvent := &protofsm.BroadcastTxn{
			Tx: closeTx,
			Label: labels.MakeLabel(
				labels.LabelTypeChannelClose, &env.Scid,
			),
		}
		daemonEvents := protofsm.DaemonEventSet{sendEvent, broadcastEvent}

		// Now that we've extracted the signature, we'll transition to
		// the next state where we'll sign+broadcast the sig.
		return &CloseStateTransition{
			NextState: &ClosePending{},
			NewEvents: fn.Some(protofsm.EmittedEvent[ProtocolEvent]{
				ExternalEvents: fn.Some(daemonEvents),
			}),
		}, nil
	}

	return nil, fmt.Errorf("%w: received %T while in RemoteCloseStart",
		ErrInvalidStateTransition, event)
}

// ProcessEvent is the event processing for out terminal state. In this state,
// we just keep looping back on ourselves.
func (c *CloseFin) ProcessEvent(event ProtocolEvent, env *Environment,
) (*CloseStateTransition, error) {

	// TODO(roasbeef): catch others here?

	return &CloseStateTransition{
		NextState: c,
	}, nil
}

// ProcessEvent...
func (c *ClosePending) ProcessEvent(event ProtocolEvent, env *Environment,
) (*CloseStateTransition, error) {

	// TODO(roasbeef): catch others here?

	return &CloseStateTransition{
		NextState: c,
	}, nil
}
