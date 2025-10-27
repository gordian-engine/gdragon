package gdna

import (
	"context"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/wingspan"
	"github.com/gordian-engine/gdragon/gdwsu"
	"github.com/gordian-engine/gordian/gcrypto"
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

	// Once we've found and recorded our own prevote,
	// don't do that work again.
	VoteRecord *voteRecord

	// Cancels the vote session and the central state.
	CancelVoting context.CancelFunc
}

// voteRecord holds some details aobut what we've done with votes
// within a single session (i.e. height and round).
type voteRecord struct {
	RecordedOwnPrevote, RecordedOwnPrecommit bool

	OwnKeyIdx     int
	ownKeyUpdated bool
}

func (r *voteRecord) NeedsProcessed(
	pubKeys []gcrypto.PubKey,
	ownPubKey gcrypto.PubKey,
) bool {
	// Trivial first checks.
	if r.RecordedOwnPrevote && r.RecordedOwnPrecommit {
		return false
	}

	// We haven't recorded our own votes.
	if !r.ownKeyUpdated {
		for i, other := range pubKeys {
			if ownPubKey.Equal(other) {
				r.OwnKeyIdx = i
				r.ownKeyUpdated = true
				break
			}
		}

		if !r.ownKeyUpdated {
			r.OwnKeyIdx = -1
			r.ownKeyUpdated = true
		}
	}

	// Own key is updated now, so a non-negative index
	// (in combination with the ealrier check that we haven't recorded
	// our own prevote and precommit)
	// means we need to check votes.
	return r.OwnKeyIdx >= 0
}
