package lnwire

import (
	"io"

	"github.com/btcsuite/btcd/btcec"
)

// RevokeAndAck is sent by either side once a CommitSig message has been
// received, and validated. This message serves to revoke the prior commitment
// transaction, which was the most up to date version until a CommitSig message
// referencing the specified ChannelPoint was received.  Additionally, this
// message also piggyback's the next revocation hash that Alice should use when
// constructing the Bob's version of the next commitment transaction (which
// would be done before sending a CommitSig message).  This piggybacking allows
// Alice to send the next CommitSig message modifying Bob's commitment
// transaction without first asking for a revocation hash initially.
type RevokeAndAck struct {
	// ChanID uniquely identifies to which currently active channel this
	// RevokeAndAck applies to.
	ChanID ChannelID

	// Revocation is the preimage to the revocation hash of the now prior
	// commitment transaction.
	Revocation [32]byte

	// NextRevocationKey is the next commitment point which should be used
	// for the next commitment transaction the remote peer creates for us.
	// This, in conjunction with revocation base point will be used to
	// create the proper revocation key used within the commitment
	// transaction.
	NextRevocationKey *btcec.PublicKey

	// ChanType is the explicit channel type that informs what type of
	// commitment is beign revoked. This is typically the same as the same
	// as the type used to open the channel. This value can change (to
	// upgrade channel types), but *only* if an UpdateCommit message is
	// sent first by both sides.
	ChanType ChannelType

	// ExtraData is the set of data that was appended to this message to
	// fill out the full maximum transport message size. These fields can
	// be used to specify optional data such as custom TLV fields.
	ExtraData ExtraOpaqueData
}

// NewRevokeAndAck creates a new RevokeAndAck message.
func NewRevokeAndAck() *RevokeAndAck {
	return &RevokeAndAck{
		ExtraData: make([]byte, 0),
	}
}

// A compile time check to ensure RevokeAndAck implements the lnwire.Message
// interface.
var _ Message = (*RevokeAndAck)(nil)

// Decode deserializes a serialized RevokeAndAck message stored in the
// passed io.Reader observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (c *RevokeAndAck) Decode(r io.Reader, pver uint32) error {
	err := ReadElements(r,
		&c.ChanID,
		c.Revocation[:],
		&c.NextRevocationKey,
	)
	if err != nil {
		return err
	}

	var tlvRecords ExtraOpaqueData
	if err := ReadElements(r, &tlvRecords); err != nil {
		return err
	}

	// TODO(roasbeef): make ChanType a pointer then check the second value
	// to set it or not?
	_, err = tlvRecords.ExtractRecords(
		&c.ChanType,
	)
	if err != nil {
		return err
	}

	c.ExtraData = tlvRecords

	return err
}

// Encode serializes the target RevokeAndAck into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the lnwire.Message interface.
func (c *RevokeAndAck) Encode(w io.Writer, pver uint32) error {
	var tlvRecords ExtraOpaqueData

	// If the set of extra data is already populated, then we'll write that
	// out as is, since we may have read this from disk and want to ensure
	// we write out the exact same bytes.
	switch {
	case len(c.ExtraData) != 0:
		tlvRecords = c.ExtraData

	// Otherwise, we're encoding this message a new, so we don't need to
	// keep track of any existing opauqe bytes.
	default:
		// Pack in the series of TLV records into this message. The
		// order we pass them in doesn't matter, as the method will
		// ensure that things are all properly sorted.
		err := tlvRecords.PackRecords(
			&c.ChanType,
		)
		if err != nil {
			return err
		}

		c.ExtraData = tlvRecords
	}

	return WriteElements(w,
		c.ChanID,
		c.Revocation[:],
		c.NextRevocationKey,
		tlvRecords,
	)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (c *RevokeAndAck) MsgType() MessageType {
	return MsgRevokeAndAck
}

// MaxPayloadLength returns the maximum allowed payload size for a RevokeAndAck
// complete message observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (c *RevokeAndAck) MaxPayloadLength(uint32) uint32 {
	return MaxMsgBody
}

// TargetChanID returns the channel id of the link for which this message is
// intended.
//
// NOTE: Part of peer.LinkUpdater interface.
func (c *RevokeAndAck) TargetChanID() ChannelID {
	return c.ChanID
}
