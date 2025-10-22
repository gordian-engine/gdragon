package gdna

import (
	"github.com/gordian-engine/dragon/dquic"
)

// Stream error codes,
// Randomly generated 8-byte values.
const (
	ProposedHeaderRejected dquic.StreamErrorCode = 0x0e03_17e1_ca1b_a826 // Decimal: 1009676999987013670
	ProposedHeaderIgnored  dquic.StreamErrorCode = 0x2cc3_32e9_8d11_6914 // Decimal: 3225477736802904340

	InternalBroadcastOperationFailure dquic.StreamErrorCode = 0x187c_35ac_904f_a05a // Decimal: 1764344169294176346

	DisconnectDueToProposedHeader dquic.ApplicationErrorCode = 0x33c3_8eca_e564_ad68 // Decimal: 3729981918476021096
)
