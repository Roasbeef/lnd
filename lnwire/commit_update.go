package lnwire

import "io"

// CommitUpdate...
//
// NOTE: This
//
// TODO(roasbeef): state machine should treat this as an UpdateFee like message
// to handle retransmission?
type CommitUpdate struct {
	// ChanID uniquely identifies to which currently active channel this
	// CommitUpdate applies to.
	ChanID ChannelID

	// NewChanType...
	NewChanType ChannelType

	// ExtraData is the set of data that was appended to this message to
	// fill out the full maximum transport message size. These fields can
	// be used to specify optional data such as custom TLV fields.
	//
	// TODO(roasbeef): if purely TLV message don't need to have this? but
	// in practice how would handle other side sending params you don't
	// understand
	ExtraData ExtraOpaqueData
}

// NewCommitUpdate...
func NewCommitUpdate(chanID ChannelID,
	newChanType ChannelType) *CommitUpdate {

	return &CommitUpdate{
		ChanID:      chanID,
		NewChanType: newChanType,
	}
}

// A compile time check to ensure CommitUpdate implements the lnwire.Message
// interface.
var _ Message = (*CommitUpdate)(nil)

// Encode serializes the target CommitUpdate into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the lnwire.Message interface.
func (c *CommitUpdate) Encode(w io.Writer, pver uint32) error {
	var tlvRecords ExtraOpaqueData

	// As this is a *pure* TLV message, if this field is already set, then
	// we don't need to re-encode things, as this means this message was
	// read from disk.
	switch {
	case len(c.ExtraData) != 0:
		tlvRecords = c.ExtraData

	// Otherwise, we'll encode the set of TLV types a new.
	default:
		// Pack in the series of TLV records into this message. The
		// order we pass them in doesn't matter, as the method will
		// ensure that things are all properly sorted.
		err := tlvRecords.PackRecords(
			//&c.ChanID, &c.NewChanType,
			&c.NewChanType, &c.ChanID,
		)
		if err != nil {
			return err
		}

		c.ExtraData = tlvRecords
	}

	return WriteElements(w, tlvRecords)
}

// Decode deserializes a serialized CommitUpdate message stored in the
// passed io.Reader observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (c *CommitUpdate) Decode(r io.Reader, pver uint32) error {
	var tlvRecords ExtraOpaqueData
	if err := ReadElements(r, &tlvRecords); err != nil {
		return err
	}

	// TODO(roasbeef): make ChanType a pointer then check the second value
	// to set it or not?
	_, err := tlvRecords.ExtractRecords(
		//&c.ChanID, &c.NewChanType,
		&c.NewChanType, &c.ChanID,
	)
	if err != nil {
		return err
	}

	c.ExtraData = tlvRecords

	return err
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (c *CommitUpdate) MsgType() MessageType {
	return MsgCommitUpdate
}

// MaxPayloadLength returns the maximum allowed payload size for a CommitUpdate
// complete message observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (c *CommitUpdate) MaxPayloadLength(uint32) uint32 {
	return MaxMsgBody
}
