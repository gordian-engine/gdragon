package gdna

import (
	"context"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/wingspan"
	"github.com/gordian-engine/gdragon/gdwsu"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
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

	// We always need a proposed header to go along with the broadcast,
	// so make it available alongside the broadcast operation.
	ProposedHeader tmconsensus.ProposedHeader
}

// sessions is the collection of header broadcasts and
// vote gossip sessions for a given round,
// as part of [sessionSet].
type sessions struct {
	// Keyed by proposer index, matching the breathcast adapter session ID scheme.
	Headers map[uint16]cancelableBroadcast

	// Prevotes and precommits are both sent in a gdwsu session.
	// TODO: this will need to change to handle aggregated vote sessions.
	VoteSession wingspan.Session[
		gdwsu.ParsedPacket, gdwsu.OutboundPacket,
		gdwsu.ReceivedFromPeer, gdwsu.UpdateFromCentral,
	]
	// We need direct access to the central state
	// to set self-originated votes
	// and to access newly received votes.
	CentralState *gdwsu.CentralState

	// Cancels the vote session and the central state.
	CancelVoting context.CancelFunc
}
