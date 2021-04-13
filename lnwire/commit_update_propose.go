package lnwire

import (
	"bytes"
	"io"

	"github.com/lightningnetwork/lnd/tlv"
)

// CommitUpdatePropose...
//
// TODO(roasbeef): every record needs to be _even_ since we need to know how to
// update all the commits?
type CommitUpdatePropose struct {
	// ChanID uniquely identifies to which currently active channel this
	// CommitUpdate applies to.
	//
	// TODO(roasbeef): redundant encoding of channel ID stuff?
	ChanID ChannelID

	// NewChanType...
	//
	// TODO(roasbeef): new and old analog?
	NewChanType ChannelType

	// Sig...
	Sig Sig

	// include new sig over update params using node pubkey?
	//  * in order to prevent spoofing

	// ExtraData is the set of data that was appended to this message to
	// fill out the full maximum transport message size. These fields can
	// be used to specify optional data such as custom TLV fields.
	//
	// TODO(roasbeef): if purely TLV message don't need to have this? but
	// in practice how would handle other side sending params you don't
	// understand
	ExtraData ExtraOpaqueData
}

// NewCommitUpdatePropose...
func NewCommitUpdatePropose(chanID ChannelID,
	newChanType ChannelType) *CommitUpdatePropose {

	return &CommitUpdatePropose{
		ChanID:      chanID,
		NewChanType: newChanType,
	}
}

// A compile time check to ensure CommitUpdatePropose implements the lnwire.Message
// interface.
var _ Message = (*CommitUpdatePropose)(nil)

// Encode serializes the target CommitUpdatePropose into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the lnwire.Message interface.
func (c *CommitUpdatePropose) Encode(w io.Writer, pver uint32) error {
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
			&c.ChanID, &c.NewChanType, &c.Sig,
		)
		if err != nil {
			return err
		}

		c.ExtraData = tlvRecords
	}

	return WriteElements(w, tlvRecords)
}

// Decode deserializes a serialized CommitUpdatePropose message stored in the
// passed io.Reader observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (c *CommitUpdatePropose) Decode(r io.Reader, pver uint32) error {
	var tlvRecords ExtraOpaqueData
	if err := ReadElements(r, &tlvRecords); err != nil {
		return err
	}

	// TODO(roasbeef): error out here if return TLV elements we don't know
	// about?
	_, err := tlvRecords.ExtractRecords(
		&c.NewChanType, &c.ChanID, &c.Sig,
	)
	if err != nil {
		return err
	}

	// TODO(roasbeef): error out if there're any extra data items we don't
	// understand?
	//  * as it's a commit change, how can we send/adhere to things we
	//  don't understand?

	c.ExtraData = tlvRecords

	return err
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (c *CommitUpdatePropose) MsgType() MessageType {
	return MsgCommitUpdatePropose
}

// MaxPayloadLength returns the maximum allowed payload size for a CommitUpdatePropose
// complete message observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (c *CommitUpdatePropose) MaxPayloadLength(uint32) uint32 {
	return MaxMsgBody
}

// DataToSign is used to retrieve part of commitment update proposal message
// that is to be signed. As this message is entirely a TLV message, we sign the
// TLV encoding of the message excluding the signature to avoid a circular
// dependency.
func (c *CommitUpdatePropose) DataToSign() ([]byte, error) {
	var w bytes.Buffer

	// We'll simply serialize this as a normal TLV message, but omit the
	// signature.
	var tlvRecords ExtraOpaqueData
	err := tlvRecords.PackRecords(
		&c.NewChanType, &c.ChanID,
	)
	if err != nil {
		return nil, err
	}

	if _, err := w.Write(tlvRecords); err != nil {
		return nil, err
	}

	// Finally, append any extra opaque data.
	//
	// TODO(roasbeef): don't need to extend since it's pure TLV and we
	// can't handle anything we don't know about?
	//
	//  * or use modified version to incrementally re-slice like initially?
	//if err := c.ExtraData.Encode(&w); err != nil {
	//	return nil, err
	//}

	return w.Bytes(), nil
}

// tlvRecords...
func (c *CommitUpdatePropose) tlvRecords() []tlv.Record {
	records := []tlv.Record{
		c.ChanID.Record(), c.NewChanType.Record(),
		c.Sig.Record(),
	}

	tlv.SortRecords(records)

	return records
}

// tlvRecordSize...
//
// TODO(roasbeef): could just hard code, but this way we don't have to update
// constants
func (c CommitUpdatePropose) tlvRecordSize() uint64 {
	var b bytes.Buffer

	// We know encoding and stream creation work as they're exercised in
	// the quick check tests.
	tlvStream, _ := tlv.NewStream(c.tlvRecords()...)
	tlvStream.Encode(&b)

	recordLen := uint64(len(b.Bytes()))

	return tlv.VarIntSize(recordLen) + recordLen
}

// eCommitUpdateProposal attempts to encode a CommitUpdatePropose message
// stored in the passed io.Writer. This implements a _nested_ TLV record as
// rather than do a normal encoding here, we'll encode a new sub TLV stream
// instead.
func eCommitUpdateProposal(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*CommitUpdatePropose); ok {
		var innerTlvBlob bytes.Buffer
		if err := v.Encode(&innerTlvBlob, 0); err != nil {
			return err
		}

		// This blob will then be prefixed with the length of the blob
		// itself to ensure that we can read just this blob and not
		// over run the entire payload.
		innerTlvLength := uint64(len(innerTlvBlob.Bytes()))
		if err := tlv.WriteVarInt(w, innerTlvLength, buf); err != nil {
			return err
		}

		if _, err := w.Write(innerTlvBlob.Bytes()); err != nil {
			return err
		}

		return nil
	}

	return tlv.NewTypeForEncodingErr(val, "lnwire.CommitUpdatePropose")
}

// dCommitUpdateProposal attempts to decode a CommitUpdatePropose message
// stored in the passed io.Reader. Decoding is actually yet another layer of
// TLV as this is intended to be used as a nested TLV record within the pure
// TLV message that is the CommitUpdateApply message.
//
// TODO(roasbeef); reject if l is wrong?
func dCommitUpdateProposal(r io.Reader, val interface{}, buf *[8]byte,
	l uint64) error {

	if v, ok := val.(*CommitUpdatePropose); ok {
		// This value is a nested TLV with a varint length prefix, so
		// first we need to read the entire varint length.
		blobLen, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// Now that we know the length of the inner TLV blob, we'll
		// create a limited reader that'll return an EOF error once the
		// end has been reaches so the stream stops consuming bytes.
		tlvReader := io.LimitedReader{
			R: r,
			N: int64(blobLen),
		}

		return v.Decode(&tlvReader, 0)
	}

	return tlv.NewTypeForEncodingErr(val, "lnwire.CommitUpdatePropose")
}
