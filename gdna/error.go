package gdna

import (
	"github.com/quic-go/quic-go"
)

// Stream error codes,
// Randomly generated 8-byte values.
const (
	ProposedHeaderRejected quic.StreamErrorCode = 0x0e03_17e1_ca1b_a826
	ProposedHeaderIgnored  quic.StreamErrorCode = 0xacc3_32e9_8d11_6914

	InternalBroadcastOperationFailure quic.StreamErrorCode = 0x187c_35ac_904f_a05a

	DisconnectDueToProposedHeader quic.ApplicationErrorCode = 0xb3c3_8eca_e564_ad68
)
