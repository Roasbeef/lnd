package lnd

import (
	"github.com/btcsuite/btcd/btcec/v2"
	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/onionmessage"
)

// sphinxOnionMsgRouter wraps the sphinx.Router to satisfy the
// onionmessage.OnionRouter interface for onion message processing.
type sphinxOnionMsgRouter struct {
	router *sphinx.Router
}

// Compile-time check that sphinxOnionMsgRouter satisfies OnionRouter.
var _ onionmessage.OnionRouter = (*sphinxOnionMsgRouter)(nil)

// ProcessOnionPacket processes an incoming onion packet using the underlying
// sphinx router.
func (s *sphinxOnionMsgRouter) ProcessOnionPacket(
	onionPkt *sphinx.OnionPacket, assocData []byte, replayData uint32,
	opts ...sphinx.ProcessOnionOpt) (*sphinx.ProcessedPacket, error) {

	return s.router.ProcessOnionPacket(
		onionPkt, assocData, replayData, opts...,
	)
}

// DecryptBlindedHopData uses the router's private key to decrypt data
// encrypted by the creator of the blinded route.
func (s *sphinxOnionMsgRouter) DecryptBlindedHopData(
	ephemPub *btcec.PublicKey,
	encryptedData []byte) ([]byte, error) {

	return s.router.DecryptBlindedHopData(ephemPub, encryptedData)
}

// NextEphemeral computes the next ephemeral key given the current ephemeral
// key and the router's private key.
func (s *sphinxOnionMsgRouter) NextEphemeral(
	ephemPub *btcec.PublicKey) (*btcec.PublicKey, error) {

	return s.router.NextEphemeral(ephemPub)
}
