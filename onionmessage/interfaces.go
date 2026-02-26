package onionmessage

import (
	"github.com/btcsuite/btcd/btcec/v2"
	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/lnwire"
)

// OnionRouter defines the sphinx router operations needed for onion message
// processing. This interface is satisfied by *sphinx.Router and allows for
// testing with mock implementations.
type OnionRouter interface {
	// ProcessOnionPacket processes an incoming onion packet. The replayData
	// parameter is passed to the ReplayLog for auxiliary data storage.
	ProcessOnionPacket(onionPkt *sphinx.OnionPacket, assocData []byte,
		replayData uint32,
		opts ...sphinx.ProcessOnionOpt) (*sphinx.ProcessedPacket, error)

	// DecryptBlindedHopData uses the router's private key to decrypt data
	// encrypted by the creator of the blinded route.
	DecryptBlindedHopData(ephemPub *btcec.PublicKey,
		encryptedData []byte) ([]byte, error)

	// NextEphemeral computes the next ephemeral key given the current
	// ephemeral key and the router's private key.
	NextEphemeral(ephemPub *btcec.PublicKey) (*btcec.PublicKey, error)
}

// OnionMessageUpdateDispatcher dispatches onion message updates to
// subscribers. This interface is satisfied by *subscribe.Server and allows for
// testing with mock implementations.
type OnionMessageUpdateDispatcher interface {
	// SendUpdate sends an update to all active subscription clients.
	SendUpdate(update any) error
}

// PeerMessageSender sends wire messages to peers identified by their
// compressed public key. This follows the gossiper pattern where the server
// implements this interface, backing it with FindPeer -> SendMessage.
type PeerMessageSender interface {
	// SendToPeer sends the message to the peer identified by pubKey. This
	// is a synchronous send that blocks until written to the wire.
	SendToPeer(pubKey [33]byte, msg lnwire.Message) error
}
