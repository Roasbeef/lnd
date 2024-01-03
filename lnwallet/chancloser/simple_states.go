package chancloser

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/protofsm"
)

var (
	// ErrInvalidStateTransition is returned when we receive an unexpected
	// event for a given state.
	ErrInvalidStateTransition = fmt.Errorf("invalid state transition")
)

// ProtocolEvent is a special interface used to create the equivalent of a
// sum-type, but using a "sealed" interface. Protocol events can be used as input to
// trigger a state transition, and also as output to trigger a new set of
// events into the very same state machine.
type ProtocolEvent interface {
	protocolSealed()
}

// ProtocolEvents is a special type constraint that enumerates all the possible
// protocol events. This is used mainly as type-level documentation, and may
// also be useful to constraint certain state transition functions.
type ProtocolEvents interface {
	SendShutdown | ShutdownReceived | ShutdownComplete | ChannelFlushed |
		SendOfferEvent | OfferReceivedEvent | LocalSigReceived |
		ConfEvent
}

// ConfEvent indicates that a relevant transaction has been confirmed in the
// main chain.
type ConfEvent struct {
	// Tx is the transaction that has been confirmed.
	Tx *wire.MsgTx

	// BlockHeight is the height of the block that confirmed the
	// transaction.
	BlockHeight uint32

	// BlockHash is the hash of the block that confirmed the transaction.
	BlockHash chainhash.Hash
}

// protocolSealed indicates that this struct is a ProtocolEvent instance.
func (c *ConfEvent) protocolSealed() {}

// SendShutdown indicates that the user wishes to co-op close the channel, so
// we should send a new shutdown message to the remote party.  From the
// ChannelActive state, this transitions us to the ChannelFlushing state.
type SendShutdown struct {
	// TODO(roasbeef): chan ID?
	fromState *ChannelActive
	toState   *ChannelFlushing

	// IdealFeeRate is the ideal fee rate we'd like to use for the closing
	// attempt.
	IdealFeeRate chainfee.SatPerVByte

	// DeliveryAddr is the address we'd like to receive the funds to. If None, then
	DeliveryAddr fn.Option[lnwire.DeliveryAddress]
}

// protocolSealed indicates that this struct is a ProtocolEvent instance.
func (s *SendShutdown) protocolSealed() {}

// ShutdownReceived indicates that we received a shutdown event so we need to
// enter the flushing state.  From the ChannelActive state, this transitions us
// to the ChannelFlushing state.
type ShutdownReceived struct {
	// BlockHeight is the height at which the shutdown message was
	// received. This is used for channel leases to determine if a co-op
	// close can occur.
	BlockHeight uint32

	// ShutdownScript is the script the remote party wants to use to
	// shutdown.
	ShutdownScript lnwire.DeliveryAddress

	// TODO(roasbeef): just make args here rather than type params? or make as
	// part of main interface for events?
	fromState *ChannelActive
	toState   *ChannelFlushing
}

// protocolSealed indicates that this struct is a ProtocolEvent instance.
func (s *ShutdownReceived) protocolSealed() {}

// ShutdownComplete is an event that indicates the channel has been fully
// shutdown. At this point, we'll go to the ChannelFlushing state so we can
// wait for all pending updates to be gone from the channel.
type ShutdownComplete struct {
	fromState *ShutdownPending
	toState   *ChannelFlushing
}

// protocolSealed indicates that this struct is a ProtocolEvent instance.
func (s *ShutdownComplete) protocolSealed() {}

// ShutdownBalances holds the local+remote balance once the channel has been
// fully flushed.
type ShutdownBalances struct {
	// LocalBalance is the local balance of the channel.
	LocalBalance lnwire.MilliSatoshi

	// RemoteBalance is the remote balance of the channel.
	RemoteBalance lnwire.MilliSatoshi
}

// ChannelFlushed is an event that indicates the channel has been fully flushed
// can we can now start closing negotiation.
type ChannelFlushed struct {
	fromState *ChannelFlushing
	toState   *ClosingNegotiation

	ShutdownBalances
}

// protocolSealed indicates that this struct is a ProtocolEvent instance.
func (c *ChannelFlushed) protocolSealed() {}

// SendOfferEvent is a self-triggered event that transitions us from the
// LocalCloseStart state to the LocalOfferSent state. This kicks off the new
// signing process for the co-op close process.
type SendOfferEvent struct {
	fromState *LocalCloseStart
	toState   *LocalOfferSent

	targetFeeRate chainfee.SatPerVByte
}

// protocolSealed indicates that this struct is a ProtocolEvent instance.
func (s *SendOfferEvent) protocolSealed() {}

// LocalSigReceived is an event that indicates we've received a signature from
// the remote party, which signs our the co-op close transaction at our
// specified fee rate.
type LocalSigReceived struct {
	fromState *LocalOfferSent
	toState   *ClosePending

	// SigMsg is the sig message we received from the remote party.
	SigMsg lnwire.ClosingSig
}

// protocolSealed indicates that this struct is a ProtocolEvent instance.
func (s *LocalSigReceived) protocolSealed() {}

// OfferReceivedEvent is an event that indicates we've received an offer from
// the remote party. This applies to the RemoteCloseStart state.
type OfferReceivedEvent struct {
	// FeeRate is the offer we received from the remote party.
	FeeRate chainfee.SatPerVByte

	// SigMsg is the signature message we received from the remote party.
	SigMsg lnwire.ClosingComplete

	fromState *RemoteCloseStart
	toState   *ClosePending
}

// protocolSealed indicates that this struct is a ProtocolEvent instance.
func (s *OfferReceivedEvent) protocolSealed() {}

// CloseSigner...
type CloseSigner interface {
	// CreateCloseProposal creates a new co-op close proposal in the form
	// of a valid signature, the chainhash of the final txid, and our final
	// balance in the created state.
	CreateCloseProposal(proposedFee btcutil.Amount,
		localDeliveryScript []byte, remoteDeliveryScript []byte,
		closeOpt ...lnwallet.ChanCloseOpt,
	) (
		input.Signature, *chainhash.Hash, btcutil.Amount, error)

	// CompleteCooperativeClose persistently "completes" the cooperative
	// close by producing a fully signed co-op close transaction.
	CompleteCooperativeClose(localSig, remoteSig input.Signature,
		localDeliveryScript, remoteDeliveryScript []byte,
		proposedFee btcutil.Amount, closeOpt ...lnwallet.ChanCloseOpt,
	) (*wire.MsgTx, btcutil.Amount, error)
}

// Environment is a set of dependencies that a state machine may need to carry
// out the logic for a given state transition. All fields are to be considered
// immutable, and will be fixed for the lifetime of the state machine.
//
// TODO(roasbef): also permit env update as well?
//   - allow latest fee update here?
type Environment struct {
	// ChainParams is the chain parameters for the channel.
	ChainParams chaincfg.Params

	// ChanPeer is the peer we're attempting to close the channel with.
	ChanPeer btcec.PublicKey

	// ChanPoint is the channel point of the active channel.
	ChanPoint wire.OutPoint

	// ChanID is the channel ID of the channel we're attempting to close.
	ChanID lnwire.ChannelID

	// ShortChanID is the short channel ID of the channel we're attempting
	// to close.
	Scid lnwire.ShortChannelID

	// ChanType is the type of channel we're attempting to close.
	ChanType channeldb.ChannelType

	// ThawHeight is the height at which the channel will be thawed. If
	// this is None, then co-op close can occur at any moment.
	ThawHeight fn.Option[uint32]

	// RemoteUprontShutdown is the upfront shutdown addr of the remote party.
	// We'll use this to validate if the remote peer is authorized to close
	// the channel with the sent addr or not.
	RemoteUpfrontShutdown fn.Option[lnwire.DeliveryAddress]

	// LocalUprontShutdown is our upfront shutdown address. If Some, then
	// we'll default to using this.
	LocalUpfrontShutdown fn.Option[lnwire.DeliveryAddress]

	// NewDeliveryScript is a function that returns a new delivery script.
	// This is used if we don't have an upfront shutdown addr, and no addr
	// was specified at closing time.
	NewDeliveryScript func() (lnwire.DeliveryAddress, error)

	// CloseSigner is the signer we'll use to sign the close transaction.
	//
	// TODO(roasbeef): reset after ChannelFlushed, or that event carries
	// the signer? yeh
	CloseSigner CloseSigner

	// FeeEstimator is the fee estimator we'll use to determine the fee in
	// satoshis we'll pay given a local and/or remote output.
	FeeEstimator CoopFeeEstimator

	// TODO(roasbeef): record last fee rate used? can use for retstart
}

// CleanUp is a method that is called once the state machine exits.
func (e *Environment) CleanUp() error {
	// TODO(roasbeef): actually clean something up
	return nil
}

// CloseStateTransition...
type CloseStateTransition = protofsm.StateTransition[ProtocolEvent, *Environment]

// ProtocolState is our sum-type ish interface that represents the current
// protocol state.
type ProtocolState interface {
	// protocolStateSealed is a special method that is used to seal the
	// interface (only types in this pacakge can implement it).
	protocolStateSealed()

	// IsTerminal returns true if the target state is a terminal state.
	IsTerminal() bool

	// TODO(roasbeef): also factor in custom env? env struct of interfaces
	// we care about, then don't need to pass around?

	// ProcessEvent takes a protocol event, and implements a state
	// transition for the state.
	ProcessEvent(ProtocolEvent, *Environment) (*CloseStateTransition, error)
}

// AsymmetricPeerState is an extension of the normal ProtocolState interface
// that gives a caller a hit on if the target state should process an incoming
// event or not.
type AsymmetricPeerState interface {
	ProtocolState

	// ShouldRouteTo returns true if the target state should process the
	// target event.
	ShouldRouteTo(ProtocolEvent) bool
}

// ProtocolStates is a special type constraint that enumerates all the possible
// protocol states.
type ProtocolStates interface {
	ChannelActive | ShutdownPending | ChannelFlushing | ClosingNegotiation |
		LocalCloseStart | LocalOfferSent | RemoteCloseStart |
		ClosePending | CloseFin
}

// ChannelActive is the base state for the channel closer state machine. In
// this state, we haven't begun the shutdown process yet, so the channel is
// still active. Receiving the ShutdownSent or ShutdownReceived events will
// transition us to the ChannelFushing state.
//
// When we transition to this state, we emit a DaemonEvent to send the shutdown
// message if we received one ourselves. Alternatively, we may send out a new
// shutdown if we're initiating it for the very first time.
//
// TODO(roasbeef): move all these to the env?
type ChannelActive struct {
	nextState *ShutdownPending

	outputDaemonEvents fn.Option[protofsm.SendMsgEvent[ProtocolEvent]]
}

// IsTerminal returns true if the target state is a terminal state.
func (c *ChannelActive) IsTerminal() bool {
	return false
}

// protocolSealed indicates that this struct is a ProtocolEvent instance.
func (c *ChannelActive) protocolStateSealed() {}

// ShutdownScripts is a set of scripts that we'll use to co-op close the
// channel.
type ShutdownScripts struct {
	// LocalDeliveryScript is the script that we'll send our settled
	// channel funds to.
	LocalDeliveryScript lnwire.DeliveryAddress

	// RemoteDeliveryScript is the script that we'll send the remote
	// party's settled channel funds to.
	RemoteDeliveryScript lnwire.DeliveryAddress
}

// ShutdownPending is the state we enter into after we've sent or received the
// shutdown message. If we sent the shutdown, then we'll wait for the remote
// party to send a shutdown. Otherwise, if we received it, then we'll send our
// shutdown then go to the next state.
type ShutdownPending struct {
	prevState *ChannelActive

	nextState *ChannelFlushing

	inputEvents fn.Either[SendShutdown, ShutdownReceived]

	ShutdownScripts
}

// IsTerminal returns true if the target state is a terminal state.
func (s *ShutdownPending) IsTerminal() bool {
	return false
}

// protocolStateSealed indicates that this struct is a ProtocolEvent instance.
func (s *ShutdownPending) protocolStateSealed() {}

// ChannelFlushing is the state we enter into after we've received or sent a
// shutdown message. In this state, we wait the ChannelFlushed event, after
// which we'll transition to the CloseReady state.
type ChannelFlushing struct {
	inputEvents fn.Either[ShutdownComplete, ShutdownReceived]

	prevState *ShutdownPending

	nextState *ClosingNegotiation

	ShutdownScripts
}

// protocolStateSealed indicates that this struct is a ProtocolEvent instance.
func (c *ChannelFlushing) protocolStateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (c *ChannelFlushing) IsTerminal() bool {
	return false
}

// ClosingNegotiation is the state we transition to once the channel has been
// flushed. This is actually a composite state that contains one for each side
// of the channel, as the closing process is asymmetric. Once either of the
// peer states reaches the CloseFin state, then the channel is fully closed,
// and we'll transition to that terminal state.
type ClosingNegotiation struct {
	prevState *ChannelFlushing

	// TODO(roasbeef): need input of ideal fee rates?
	peerState DualPeerState

	nextState *CloseFin
}

// IsTerminal returns true if the target state is a terminal state.
func (c *ClosingNegotiation) IsTerminal() bool {
	return false
}

// protocolSealed indicates that this struct is a ProtocolEvent instance.
func (c *ClosingNegotiation) protocolStateSealed() {}

// CloseChannelTerms...
type CloseChannelTerms struct {
	ShutdownBalances

	ShutdownScripts
}

// DeriveCloseTxOuts takes the close terms, and returns the local and remote tx
// out for the close transaction. If an output is dust, then it'll be nil.
//
// TODO(roasbeef): add func for w/e heuristic to not manifest own output?
func (c *CloseChannelTerms) DeriveCloseTxOuts() (*wire.TxOut, *wire.TxOut) {
	deriveTxOut := func(balance btcutil.Amount, pkScript []byte) *wire.TxOut {
		dustLimit := lnwallet.DustLimitForSize(len(pkScript))
		if balance < dustLimit {
			return &wire.TxOut{
				PkScript: pkScript,
				Value:    int64(balance),
			}
		}

		return nil
	}

	localTxOut := deriveTxOut(
		c.LocalBalance.ToSatoshis(),
		c.LocalDeliveryScript,
	)
	remoteTxOut := deriveTxOut(
		c.RemoteBalance.ToSatoshis(),
		c.RemoteDeliveryScript,
	)

	return localTxOut, remoteTxOut
}

// RemoteAmtIsDust returns true if the remote output is dust.
func (c *CloseChannelTerms) RemoteAmtIsDust() bool {
	return c.RemoteBalance.ToSatoshis() < lnwallet.DustLimitForSize(
		len(c.RemoteDeliveryScript),
	)
}

// LocalAmtIsDust returns true if the local output is dust.
func (c *CloseChannelTerms) LocalAmtIsDust() bool {
	return c.LocalBalance.ToSatoshis() < lnwallet.DustLimitForSize(
		len(c.LocalDeliveryScript),
	)
}

// LocalCloseStart is the state we enter into after we've received or sent
// shutdown, and the channel has been flushed. In this state, we'll emit a new
// event to send our offer to drive the rest of the process.
type LocalCloseStart struct {
	targetFeeRate chainfee.SatPerVByte

	// TODO(roasbeef): make into a typ type param again?
	outputEvent *SendOfferEvent

	CloseChannelTerms
}

// ShouldRouteTo returns true if the target state should process the target
// event.
func (l *LocalCloseStart) ShouldRouteTo(event ProtocolEvent) bool {
	switch event.(type) {
	case *SendOfferEvent:
		return true
	default:
		return false
	}
}

// IsTerminal returns true if the target state is a terminal state.
func (l *LocalCloseStart) IsTerminal() bool {
	return false
}

// protocolStateaSealed indicates that this struct is a ProtocolEvent instance.
func (l *LocalCloseStart) protocolStateSealed() {}

// A compile-time assertion to ensure LocalCloseStart satisfies the
// AsymmetricPeerState interface.
var _ AsymmetricPeerState = (*LocalCloseStart)(nil)

// LocalOfferSent is the state we transition to after we reveiver the
// SendOfferEvent in the LocalCloseStart state. With this state we send our
// offer to the remote party, then await a sig from them which concludes the
// local cooperative close process.
type LocalOfferSent struct {
	prevState *LocalCloseStart

	transitionEvent *SendOfferEvent

	nextState ClosePending

	outputDaemonEvents protofsm.SendMsgEvent[ProtocolEvent]

	// ProposedFee is the fee we proposed to the remote party.
	ProposedFee btcutil.Amount

	// LocalSig is the signature we sent to the remote party.
	LocalSig lnwire.Sig

	CloseChannelTerms
}

// ShouldRouteTo returns true if the target state should process the target
// event.
func (l *LocalOfferSent) ShouldRouteTo(event ProtocolEvent) bool {
	switch event.(type) {
	case *LocalSigReceived:
		return true
	default:
		return false
	}
}

// protocolStateaSealed indicates that this struct is a ProtocolEvent instance.
func (l *LocalOfferSent) protocolStateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (l *LocalOfferSent) IsTerminal() bool {
	return false
}

// A compile-time assertion to ensure LocalOfferSent satisfies the
// AsymmetricPeerState interface.
var _ AsymmetricPeerState = (*LocalOfferSent)(nil)

// ClosePending is the state we enter after concluding the negotiation for the
// remote or local state. At this point, given a confirmation notification we
// can terminate the process. Otherwise, we can receive a fresh CoopCloseReq to
// go back to the very start.
type ClosePending struct {
	transitionEvents fn.Either[LocalSigReceived, OfferReceivedEvent]

	nextState fn.Either[CloseFin, ChannelFlushing]

	outputDaemonEvents fn.Option[protofsm.BroadcastTxn]
}

// protocolStateSealed indicates that this struct is a ProtocolEvent instance.
func (c *ClosePending) protocolStateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (c *ClosePending) IsTerminal() bool {
	return true
}

// CloseFin is the terminal state for the channel closer state machine. At this
// point, the close tx has been confirmed on chain.
type CloseFin struct {
	transitionEvent *ConfEvent
}

// protocolStateSealed indicates that this struct is a ProtocolEvent instance.
func (c *CloseFin) protocolStateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (c *CloseFin) IsTerminal() bool {
	return true
}

// RemoteCloseStart is similar to the LocalCloseStart, but is used to drive the
// process of signing an offer for the remote party
type RemoteCloseStart struct {
	peerPub btcec.PublicKey

	nextState *ClosePending

	CloseChannelTerms
}

// ShouldRouteTo returns true if the target state should process the target
// event.
func (l *RemoteCloseStart) ShouldRouteTo(event ProtocolEvent) bool {
	switch event.(type) {
	case *OfferReceivedEvent:
		return true
	default:
		return false
	}
}

// protocolStateSealed indicates that this struct is a ProtocolEvent instance.
func (c *RemoteCloseStart) protocolStateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (c *RemoteCloseStart) IsTerminal() bool {
	return false
}

// A compile-time assertion to ensure RemoteCloseStart satisfies the
// AsymmetricPeerState interface.
var _ AsymmetricPeerState = (*LocalOfferSent)(nil)

// DualPeerState is a special state that allows us to treat two states as a
// single state. We'll use the ShouldRouteTo method to determine which state
// route incoming events to.
type DualPeerState struct {
	localState  AsymmetricPeerState
	remoteState AsymmetricPeerState
}

// ConfWrapper is a wrapper around the protocol state that allows us to short
// circuit anytime a confirmation is received.
type ConfWrapper struct {
	innerState ProtocolState
}
