package gdna

import (
	"context"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/wingspan"
	"github.com/gordian-engine/gdragon/gdwsu"
)

// sessionSet is used within the [Strategy]
// to track active proposed header broadcast sessions
// and vote gossip sessions.
type sessionSet map[hr]sessions

// hr is the height-round key used for [sessionSet].
type hr struct {
	H uint64
	R uint32
}

// cancelableBroadcast contains a broadcast operation
// and an associated cancel func to stop the operation.
//
// This type is used for tracking live operations in a [sessions] value.
type cancelableBroadcast struct {
	Op     *breathcast.BroadcastOperation
	Cancel context.CancelFunc
}

// sessions is the collection of header broadcasts and
// vote gossip sessions for a given round,
// as part of [sessionSet].
type sessions struct {
	// Keyed by block hash, matching the breathcast adapter session ID scheme.
	Headers map[string]cancelableBroadcast

	// Prevotes and precommits are both sent in a gdwsu session.
	// TODO: this will need to change to handle aggregated vote sessions.
	VoteSession wingspan.Session[
		gdwsu.ParsedPacket, gdwsu.OutboundPacket,
		gdwsu.ReceivedFromPeer, gdwsu.UpdateFromCentral,
	]
	CancelVoting context.CancelFunc
}
