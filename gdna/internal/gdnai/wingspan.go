package gdnai

import (
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dquic"
)

// IncomingWingspanStream is the value sent from the [StreamAccepter]
// back to the network adapter upon successfully extracting header values
// from a wingspan protocol stream.
type IncomingWingspanStream struct {
	// The already extracted session ID from the stream.
	SessionHeight uint64
	SessionRound  uint32

	Conn dconn.Conn

	Stream dquic.ReceiveStream
}
