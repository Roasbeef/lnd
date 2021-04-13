package lnwire

import "github.com/lightningnetwork/lnd/tlv"

// recordProducer...
type recordProducer struct {
	record tlv.Record
}

// Record...
func (r *recordProducer) Record() tlv.Record {
	return r.record
}

func newRecordProducer(record tlv.Record) *recordProducer {
	return &recordProducer{
		record: record,
	}
}
