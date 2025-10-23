package gdnai

import "github.com/gordian-engine/gdragon/gdbc"

// BreathcastCheck is the value sent from the [streamAccepter]
// to the [NetworkAdapter], for a fast check on whether a broadcast
// matches an existing session or whether it needs to be fully parsed.
type BreathcastCheck struct {
	BroadcastID gdbc.BroadcastID

	AppHeader []byte

	CheckResult chan BreathcastCheckResult
}

// BreathcastCheckResult is the result value for [BreathcastCheck]
// sent from the NetworkAdapter to the [StreamAccepter].
type BreathcastCheckResult uint8

const (
	// TODO: probably need more granular reject states.
	// One to indicate "too old" but otherwise valid,
	// another for something like malformed, maybe?
	BreathcastCheckRejected BreathcastCheckResult = iota

	// Accepted by the NetworkAdapter;
	// no further work needed in the streamAccepter.
	BreathcastCheckAccepted

	// Unrecognized by the NetworkAdapter but possibly valid.
	// The streamAccepter needs to fully process the value.
	BreathcastCheckNeedsProcessed
)
