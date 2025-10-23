package gdbc

import (
	"encoding/binary"
	"io"
)

// The size of broadast IDs (64-bit height, 32-bit round, and 16-bit proposer ID).
// This is required for configuring the breathcast protocol instance.
const BroadcastIDLen = 8 + 4 + 2

// BroadcastID is the structured broadcast ID used by the [Adapter].
type BroadcastID struct {
	Height      uint64
	Round       uint32
	ProposerIdx uint16
}

// Parse populates the fields on the broadcast ID
// based on the raw bytes in b.
//
// If b is too short, [io.ErrUnexpectedEOF] is returned.
func (id *BroadcastID) Parse(b []byte) error {
	if len(b) < BroadcastIDLen {
		return io.ErrUnexpectedEOF
	}

	id.Height = binary.BigEndian.Uint64(b)
	id.Round = binary.BigEndian.Uint32(b[8:])
	id.ProposerIdx = binary.BigEndian.Uint16(b[8+4:])

	return nil
}

// Append encodes and appends the values in the broadcast ID
// to the given destination slice,
// reallocating if dst lacks necessary capacity.
func (id BroadcastID) Append(dst []byte) []byte {
	if cap(dst) < BroadcastIDLen {
		dst = make([]byte, 0, BroadcastIDLen)
	}
	dst = binary.BigEndian.AppendUint64(dst, id.Height)
	dst = binary.BigEndian.AppendUint32(dst, id.Round)
	dst = binary.BigEndian.AppendUint16(dst, id.ProposerIdx)
	return dst
}
