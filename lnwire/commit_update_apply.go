package lnwire

import (
	"fmt"
	"io"

	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// LocalProposalRecordType...
	//
	// TODO(roasbeef): make all into even so all required?
	LocalProposalRecordType = 1

	// RemoteProposalRecordType...
	RemoteProposalRecordType = 3
)

// CommitUpdateApply...
//
// NOTE: This
//
// TODO(roasbeef): state machine should treat this as an UpdateFee like message
// to handle retransmission?
//
//  * shoudl also echo back params?
type CommitUpdateApply struct {
	// ChanID uniquely identifies to which currently active channel this
	// CommitUpdateApply applies to.
	ChanID ChannelID

	// LocalProposal...
	LocalProposal *CommitUpdatePropose

	// RemoteProposal...
	RemoteProposal *CommitUpdatePropose

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

// TODO(roasbeef): two messages?
//  * CommitUpdateApply -> (next sig doesn't include changes)
//  * <- CommitUpdateApplyACK (sig still doesn't include changes)
//  * <- CommitUpdateApplyNACK (or merge w/ reply, means a no-op, other side doesn't
//  want to budge for w/e reason)
//  * CommitUpdateApply -> (w/ propose bit off or commit bit on?)
//  * Sig -> (covers new set of updates)
//  * if no ACK sent then updates are a no go
//  * if ACK sent then next commit covers that?
//
//  * if both sides send, then random back off and send again?
//  * allows all to be safely retransmit? (or just use the same message?)
//  * the ACK contains a commitment to the prior contents?

// TODO(roasbeef): new form: CommitUpdateApplyPropose -> CommitUpdateApply
//  * shutdown like message at the top layer (doesn't need HTLCs to be blank)
//    * lets one side reject and back out if they need to
//  * if reply then
//  * after both sides receive initaitor sends CommitUpdateApplyACK (or w/e ) w/ a sig
//  * includes config of both sides if needed

// NewCommitUpdateApply...
func NewCommitUpdateApply(chanID ChannelID,
	localProposal, remoteProposal *CommitUpdatePropose) *CommitUpdateApply {

	return &CommitUpdateApply{
		ChanID:         chanID,
		LocalProposal:  localProposal,
		RemoteProposal: remoteProposal,
	}
}

// A compile time check to ensure CommitUpdateApply implements the lnwire.Message
// interface.
var _ Message = (*CommitUpdateApply)(nil)

// Encode serializes the target CommitUpdateApply into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the lnwire.Message interface.
func (c *CommitUpdateApply) Encode(w io.Writer, pver uint32) error {
	var tlvRecords ExtraOpaqueData

	// As this is a *pure* TLV message, if this field is already set, then
	// we don't need to re-encode things, as this means this message was
	// read from disk.
	switch {
	case len(c.ExtraData) != 0:
		tlvRecords = c.ExtraData

	// Otherwise, we'll encode the set of TLV types a new.
	default:
		records := []tlv.RecordProducer{&c.ChanID}

		// As only the initiator of the transaction can send out this
		// message the remote party is the responder. This must ALWAYS
		// be included, while the local proposal may be omitted to
		// allow a fast path where only the responder has updates to
		// add.
		remoteProposalRecord := tlv.MakeDynamicRecord(
			RemoteProposalRecordType, c.RemoteProposal,
			c.RemoteProposal.tlvRecordSize, eCommitUpdateProposal,
			dCommitUpdateProposal,
		)
		records = append(
			records, newRecordProducer(remoteProposalRecord),
		)

		// If the initiator also has an update to apply, then we'll
		// construct a record for them as well.
		if c.LocalProposal != nil {
			localProposalRecord := tlv.MakeDynamicRecord(
				LocalProposalRecordType, c.LocalProposal,
				c.LocalProposal.tlvRecordSize,
				eCommitUpdateProposal, dCommitUpdateProposal,
			)
			records = append(
				records, newRecordProducer(localProposalRecord),
			)
		}

		// Pack in the series of TLV records into this message. The
		// order we pass them in doesn't matter, as the method will
		// ensure that things are all properly sorted.
		err := tlvRecords.PackRecords(records...)
		if err != nil {
			fmt.Println("fail encode")
			return err
		}

		c.ExtraData = tlvRecords
	}

	return WriteElements(w, tlvRecords)
}

// Decode deserializes a serialized CommitUpdateApply message stored in the
// passed io.Reader observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (c *CommitUpdateApply) Decode(r io.Reader, pver uint32) error {
	var tlvRecords ExtraOpaqueData
	if err := ReadElements(r, &tlvRecords); err != nil {
		return err
	}

	localPropose := CommitUpdatePropose{}
	remotePropose := CommitUpdatePropose{}
	records := []tlv.RecordProducer{
		&c.ChanID,
		newRecordProducer(tlv.MakeDynamicRecord(
			RemoteProposalRecordType, &remotePropose,
			nil, eCommitUpdateProposal, dCommitUpdateProposal,
		)),
		newRecordProducer(tlv.MakeDynamicRecord(
			LocalProposalRecordType, &localPropose,
			nil, eCommitUpdateProposal, dCommitUpdateProposal,
		)),
	}

	// TODO(roasbeef): need to encode as distinct streams

	parsedTypes, err := tlvRecords.ExtractRecords(records...)
	if err != nil {
		fmt.Println("fail decode")
		return err
	}

	// The local proposal may not always exist, so we only set the value to
	// a non-nil pointer if we actually decoded it.
	if v, ok := parsedTypes[LocalProposalRecordType]; ok && v == nil {
		c.LocalProposal = &localPropose
	}

	c.RemoteProposal = &remotePropose

	c.ExtraData = tlvRecords

	return err
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (c *CommitUpdateApply) MsgType() MessageType {
	return MsgCommitUpdateApply
}

// MaxPayloadLength returns the maximum allowed payload size for a CommitUpdateApply
// complete message observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (c *CommitUpdateApply) MaxPayloadLength(uint32) uint32 {
	return MaxMsgBody
}

// TargetChanID returns the channel id of the link for which this message is
// intended.
//
// NOTE: Part of peer.LinkUpdater interface.
func (c *CommitUpdateApply) TargetChanID() ChannelID {
	return c.ChanID
}
