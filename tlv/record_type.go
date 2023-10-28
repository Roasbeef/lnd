package tlv

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningnetwork/lnd/fn"
	"golang.org/x/exp/constraints"
)

// RecordT is a high-order type makes it easy to encode known "primitive" types
// as TLV records.
type RecordT[T TlvTypes, V any] struct {
	// recordType is the type of the TLV record.
	recordType T

	// val is the value of the underlying record. Go doesn't let us just
	// embed the type param as a struct field, so we need an intermediate
	// variable.
	Val V
}

// NewRecordT creates a new RecordT type from a given RecordProducer type. This
// is useful to wrap a given record in this utility type, which also serves as
// an extra type annotation. The underlying type of the record is retained.
func NewRecordT[T TlvTypes, V RecordProducer](record V) RecordT[T, V] {
	return RecordT[T, V]{
		Val: record,
	}
}

// Primitive is a type constraint that capture the set of "primitive" types,
// which are the built in stdlib types, and type defs of those types
type Primitive interface {
	constraints.Unsigned | ~[]byte | ~[32]byte | ~[33]byte | ~bool |
		~*btcec.PublicKey | ~[64]byte
}

// NewPrimitiveRecord creates a new RecordT type from a given primitive type.
func NewPrimitiveRecord[T TlvTypes, V Primitive](val V) RecordT[T, V] {
	return RecordT[T, V]{
		Val: val,
	}
}

// Record returns the underlying record interface for the record type.
func (t *RecordT[T, V]) Record() Record {
	// Go doesn't allow type assertions on a type param, so to work around
	// this, we'll convert to any, then do our type assertion.
	tlvRecord, ok := any(t.Val).(RecordProducer)
	if !ok {
		return MakePrimitiveRecord(GetTypeVal(t.recordType), &t.Val)
	}

	return tlvRecord.Record()
}

// OptionalRecordT is a high-order type that represents an optional TLV record.
// This can be used when a TLV record doesn't always need to be present (ok to
// be odd).
type OptionalRecordT[T TlvTypes, V any] struct {
	fn.Option[RecordT[T, V]]
}

func ZeroRecordT[T TlvTypes, V any]() RecordT[T, V] {
	var v V
	return RecordT[T, V]{
		Val: v,
	}
}
