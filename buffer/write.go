package buffer

import (
	"github.com/lightningnetwork/lnd/lnwire"
)

// WriteSize represents the size needed for the maximum encrypted message in
// brontide. This includes the maximum plaintext size plus the 16-byte MAC
// that is added by the AEAD encryption.
const WriteSize = lnwire.MaxSliceLength + 16

// Write is a static byte array sized to hold the maximum encrypted message
// including the MAC overhead.
type Write [WriteSize]byte

// Recycle zeroes the Write, making it fresh for another use.
func (b *Write) Recycle() {
	RecycleSlice(b[:])
}
