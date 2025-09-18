package gdwsu_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/wingspan"
	"github.com/gordian-engine/dragon/wingspan/wingspantest"
	"github.com/gordian-engine/gdragon/gdwsu"
	"github.com/gordian-engine/gordian/gcrypto"
	"github.com/gordian-engine/gordian/gcrypto/gcryptotest"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
	"github.com/gordian-engine/gordian/tm/tmconsensus/tmconsensustest"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

// Two peers, each originating their own prevote and precommit.
func TestSession_pairedVotes(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const protocolID byte = 0x99 // Arbitrary for test.

	pfx := wingspantest.NewProtocolFixture[
		gdwsu.ParsedPacket, gdwsu.OutboundPacket,
		gdwsu.ReceivedFromPeer, gdwsu.UpdateFromCentral,
	](t, ctx, wingspantest.ProtocolFixtureConfig{
		Nodes:           2,
		ProtocolID:      protocolID,
		SessionIDLength: 8 + 4,
	})

	const height = 100
	const round = 2

	sid := make([]byte, 8+4)
	binary.BigEndian.PutUint64(sid, height)
	binary.BigEndian.PutUint32(sid[8:], round)

	signers := gcryptotest.DeterministicEd25519Signers(2)
	pubKeys := make([]gcrypto.PubKey, len(signers))
	for i, s := range signers {
		pubKeys[i] = s.PubKey()
	}

	const edSigLen = 64
	const blakeHashLen = 32

	// Set up the state and session for each node.
	cs0, d0 := gdwsu.NewCentralState(
		ctx,
		height, round,
		pubKeys,
		edSigLen, blakeHashLen,
		tmconsensustest.SimpleSignatureScheme{},
	)
	sess0, err := pfx.Protocols[0].NewSession(
		ctx,
		sid,
		[]byte("ah0"),
		cs0, d0,
	)
	require.NoError(t, err)
	defer sess0.Cancel()

	cs1, d1 := gdwsu.NewCentralState(
		ctx,
		height, round,
		pubKeys,
		edSigLen, blakeHashLen,
		tmconsensustest.SimpleSignatureScheme{},
	)
	sess1, err := pfx.Protocols[1].NewSession(
		ctx,
		sid,
		[]byte("ah1"),
		cs1, d1,
	)
	require.NoError(t, err)
	defer sess1.Cancel()

	// Now, each side needs to accept the incoming stream.
	// Order doesn't matter.
	c01, c10 := pfx.ListenerSet.Dial(t, 0, 1)

	pfx.AddConnection(c01, 0, 1)
	pfx.AddConnection(c10, 1, 0)

	acceptCtx, acceptCancel := context.WithTimeout(ctx, time.Second)
	defer acceptCancel()

	s01, err := c10.AcceptUniStream(acceptCtx)
	require.NoError(t, err)

	s10, err := c01.AcceptUniStream(acceptCtx)
	require.NoError(t, err)

	// We have to parse the headers from the stream before we can add it to the session.
	// First the protocol.
	var b1 [1]byte
	_, err = io.ReadFull(s01, b1[:])
	require.NoError(t, err)
	require.Equal(t, protocolID, b1[0])
	_, err = io.ReadFull(s10, b1[:])
	require.NoError(t, err)
	require.Equal(t, protocolID, b1[0])

	// Then the session ID.
	sBuf, err := pfx.Protocols[1].ExtractStreamSessionID(s01, nil)
	require.NoError(t, err)
	require.Equal(t, sid, sBuf)
	sBuf, err = pfx.Protocols[0].ExtractStreamSessionID(s10, nil)
	require.NoError(t, err)
	require.Equal(t, sid, sBuf)

	// Then the application header.
	ahBuf, err := wingspan.ExtractStreamApplicationHeader(s01, nil)
	require.NoError(t, err)
	require.Equal(t, "ah0", string(ahBuf))
	ahBuf, err = wingspan.ExtractStreamApplicationHeader(s10, nil)
	require.NoError(t, err)
	require.Equal(t, "ah1", string(ahBuf))

	// Now finally, the sessions can accept the streams.
	require.NoError(t, sess0.AcceptStream(
		ctx,
		dconn.Conn{
			QUIC:  c10,
			Chain: pfx.ListenerSet.Leaves[1].Chain,
		},
		s10,
	))
	require.NoError(t, sess1.AcceptStream(
		ctx,
		dconn.Conn{
			QUIC:  c01,
			Chain: pfx.ListenerSet.Leaves[0].Chain,
		},
		s01,
	))

	blockHash := strings.Repeat("a", blakeHashLen)
	// Sign a prevote for key 0, and add it to central state 0.
	vt := tmconsensus.VoteTarget{
		Height:    height,
		Round:     round,
		BlockHash: blockHash,
	}

	signContent, err := tmconsensus.PrevoteSignBytes(vt, tmconsensustest.SimpleSignatureScheme{})
	require.NoError(t, err)
	sig0, err := signers[0].Sign(ctx, signContent)
	require.NoError(t, err)

	require.NoError(t, cs0.AddLocalPrevote(ctx, 0, []byte(blockHash), sig0))

	// First, the update is available from central state 0.
	d0 = requirePubSubUpdate(t, d0, gdwsu.UpdateFromCentral{
		KeyIdx:      0,
		IsPrecommit: false,
	})

	// Then, the update has been sent to cs1 as well.
	d1 = requirePubSubUpdate(t, d1, gdwsu.UpdateFromCentral{
		KeyIdx:      0,
		IsPrecommit: false,
	})

	// Now go the other direction.
	sig1, err := signers[1].Sign(ctx, signContent)
	require.NoError(t, err)

	require.NoError(t, cs1.AddLocalPrevote(ctx, 1, []byte(blockHash), sig1))

	d1 = requirePubSubUpdate(t, d1, gdwsu.UpdateFromCentral{
		KeyIdx:      1,
		IsPrecommit: false,
	})

	d0 = requirePubSubUpdate(t, d0, gdwsu.UpdateFromCentral{
		KeyIdx:      1,
		IsPrecommit: false,
	})

	// Now, precommits.
	signContent, err = tmconsensus.PrecommitSignBytes(vt, tmconsensustest.SimpleSignatureScheme{})
	require.NoError(t, err)
	sig0, err = signers[0].Sign(ctx, signContent)
	require.NoError(t, err)

	require.NoError(t, cs0.AddLocalPrecommit(ctx, 0, []byte(blockHash), sig0))

	d0 = requirePubSubUpdate(t, d0, gdwsu.UpdateFromCentral{
		KeyIdx:      0,
		IsPrecommit: true,
	})

	d1 = requirePubSubUpdate(t, d1, gdwsu.UpdateFromCentral{
		KeyIdx:      0,
		IsPrecommit: true,
	})

	sig1, err = signers[1].Sign(ctx, signContent)
	require.NoError(t, err)

	require.NoError(t, cs1.AddLocalPrecommit(ctx, 1, []byte(blockHash), sig1))

	d1 = requirePubSubUpdate(t, d1, gdwsu.UpdateFromCentral{
		KeyIdx:      1,
		IsPrecommit: true,
	})

	d0 = requirePubSubUpdate(t, d0, gdwsu.UpdateFromCentral{
		KeyIdx:      1,
		IsPrecommit: true,
	})
}

func TestSession_votes_hop(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const protocolID byte = 0x99 // Arbitrary for test.

	pfx := wingspantest.NewProtocolFixture[
		gdwsu.ParsedPacket, gdwsu.OutboundPacket,
		gdwsu.ReceivedFromPeer, gdwsu.UpdateFromCentral,
	](t, ctx, wingspantest.ProtocolFixtureConfig{
		Nodes:           3,
		ProtocolID:      protocolID,
		SessionIDLength: 8 + 4,
	})

	const height = 200
	const round = 4

	sid := make([]byte, 8+4)
	binary.BigEndian.PutUint64(sid, height)
	binary.BigEndian.PutUint32(sid[8:], round)

	signers := gcryptotest.DeterministicEd25519Signers(3)
	pubKeys := make([]gcrypto.PubKey, len(signers))
	for i, s := range signers {
		pubKeys[i] = s.PubKey()
	}

	const edSigLen = 64
	const blakeHashLen = 32

	css := make([]*gdwsu.CentralState, 3)
	ds := make([]*dpubsub.Stream[gdwsu.UpdateFromCentral], 3)
	sessions := make([]wingspan.Session[
		gdwsu.ParsedPacket, gdwsu.OutboundPacket,
		gdwsu.ReceivedFromPeer, gdwsu.UpdateFromCentral,
	], 3)
	for i := range 3 {
		css[i], ds[i] = gdwsu.NewCentralState(
			ctx,
			height, round,
			pubKeys,
			edSigLen, blakeHashLen,
			tmconsensustest.SimpleSignatureScheme{},
		)

		var err error
		sessions[i], err = pfx.Protocols[i].NewSession(
			ctx, sid, []byte(fmt.Sprintf("ah%d", i)), css[i], ds[i],
		)
		require.NoError(t, err)
		defer sessions[i].Cancel()
	}

	// Connect the nodes as 0 <--> 1 <--> 2.
	c01, c10 := pfx.ListenerSet.Dial(t, 0, 1)
	pfx.AddConnection(c01, 0, 1)
	pfx.AddConnection(c10, 1, 0)

	c12, c21 := pfx.ListenerSet.Dial(t, 1, 2)
	pfx.AddConnection(c12, 1, 2)
	pfx.AddConnection(c21, 2, 1)

	acceptCtx, acceptCancel := context.WithTimeout(ctx, time.Second)
	defer acceptCancel()

	s01, err := c10.AcceptUniStream(acceptCtx)
	require.NoError(t, err)

	s10, err := c01.AcceptUniStream(acceptCtx)
	require.NoError(t, err)

	s21, err := c12.AcceptUniStream(acceptCtx)
	require.NoError(t, err)

	s12, err := c21.AcceptUniStream(acceptCtx)
	require.NoError(t, err)

	streams := []quic.ReceiveStream{
		s01, s10, s12, s21,
	}

	// We have to parse the headers from the stream before we can add it to the session.
	// First the protocol.
	var b1 [1]byte
	for _, s := range streams {
		_, err := io.ReadFull(s, b1[:])
		require.NoError(t, err)
		require.Equal(t, protocolID, b1[0])
	}

	// The session IDs.
	// Technically it shouldn't matter which protocol instance we use,
	// but it feels more correct to match them properly.
	sBuf, err := pfx.Protocols[1].ExtractStreamSessionID(s01, nil)
	require.NoError(t, err)
	require.Equal(t, sid, sBuf)
	sBuf, err = pfx.Protocols[0].ExtractStreamSessionID(s10, nil)
	require.NoError(t, err)
	require.Equal(t, sid, sBuf)
	sBuf, err = pfx.Protocols[1].ExtractStreamSessionID(s21, nil)
	require.NoError(t, err)
	require.Equal(t, sid, sBuf)
	sBuf, err = pfx.Protocols[2].ExtractStreamSessionID(s12, nil)
	require.NoError(t, err)
	require.Equal(t, sid, sBuf)

	// Then the application header.
	ahBuf, err := wingspan.ExtractStreamApplicationHeader(s01, nil)
	require.NoError(t, err)
	require.Equal(t, "ah0", string(ahBuf))
	ahBuf, err = wingspan.ExtractStreamApplicationHeader(s10, nil)
	require.NoError(t, err)
	require.Equal(t, "ah1", string(ahBuf))
	ahBuf, err = wingspan.ExtractStreamApplicationHeader(s12, nil)
	require.NoError(t, err)
	require.Equal(t, "ah1", string(ahBuf))
	ahBuf, err = wingspan.ExtractStreamApplicationHeader(s21, nil)
	require.NoError(t, err)
	require.Equal(t, "ah2", string(ahBuf))

	// Now the sessions can accept the streams.
	require.NoError(t, sessions[0].AcceptStream(
		ctx,
		dconn.Conn{
			QUIC:  c10,
			Chain: pfx.ListenerSet.Leaves[1].Chain,
		},
		s10,
	))

	require.NoError(t, sessions[1].AcceptStream(
		ctx,
		dconn.Conn{
			QUIC:  c01,
			Chain: pfx.ListenerSet.Leaves[0].Chain,
		},
		s01,
	))
	require.NoError(t, sessions[1].AcceptStream(
		ctx,
		dconn.Conn{
			QUIC:  c21,
			Chain: pfx.ListenerSet.Leaves[2].Chain,
		},
		s21,
	))

	require.NoError(t, sessions[2].AcceptStream(
		ctx,
		dconn.Conn{
			QUIC:  c12,
			Chain: pfx.ListenerSet.Leaves[1].Chain,
		},
		s12,
	))

	blockHash := strings.Repeat("b", blakeHashLen)
	// Sign a prevote for key 0, and add it to central state 0.
	vt := tmconsensus.VoteTarget{
		Height:    height,
		Round:     round,
		BlockHash: blockHash,
	}

	signContent, err := tmconsensus.PrevoteSignBytes(vt, tmconsensustest.SimpleSignatureScheme{})
	require.NoError(t, err)

	sig0, err := signers[0].Sign(ctx, signContent)
	require.NoError(t, err)
	require.NoError(t, css[0].AddLocalPrevote(ctx, 0, []byte(blockHash), sig0))

	// All the nodes see the update.
	for i := range ds {
		ds[i] = requirePubSubUpdate(t, ds[i], gdwsu.UpdateFromCentral{
			KeyIdx:      0,
			IsPrecommit: false,
		})
	}

	sig2, err := signers[2].Sign(ctx, signContent)
	require.NoError(t, err)
	require.NoError(t, css[2].AddLocalPrevote(ctx, 2, []byte(blockHash), sig2))
	for i := range ds {
		ds[i] = requirePubSubUpdate(t, ds[i], gdwsu.UpdateFromCentral{
			KeyIdx:      2,
			IsPrecommit: false,
		})
	}

	// Then if the middle node sends the precommit, everyone sees that too.
	signContent, err = tmconsensus.PrecommitSignBytes(vt, tmconsensustest.SimpleSignatureScheme{})
	require.NoError(t, err)

	sig1, err := signers[1].Sign(ctx, signContent)
	require.NoError(t, err)
	require.NoError(t, css[1].AddLocalPrecommit(ctx, 1, []byte(blockHash), sig1))

	for i := range ds {
		ds[i] = requirePubSubUpdate(t, ds[i], gdwsu.UpdateFromCentral{
			KeyIdx:      1,
			IsPrecommit: true,
		})
	}
}

func requirePubSubUpdate[S any](
	t *testing.T,
	s *dpubsub.Stream[S],
	exp S,
) *dpubsub.Stream[S] {
	t.Helper()

	select {
	case <-s.Ready:
		// Okay.
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Timed out waiting for ready signal on %v", s)
	}

	require.Equal(t, exp, s.Val)

	return s.Next
}
