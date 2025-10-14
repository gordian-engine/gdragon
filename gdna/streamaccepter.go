package gdna

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/gdragon/gdbc"
	"github.com/gordian-engine/gordian/tm/tmcodec"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
	"github.com/quic-go/quic-go"
)

const readProtocolIDTimeout = 50 * time.Millisecond

// streamAccepterBase contains the unchanging base values for a [streamAccepter].
type streamAccepterBase struct {
	AcceptedStreamCh    chan<- AcceptedStream
	AcceptedUniStreamCh chan<- AcceptedUniStream

	// The streamAccepter instances send on this channel,
	// and the NetworkAdapter receives on it.
	BreathcastCheck chan breathcastCheck

	Unmarshaler tmcodec.Unmarshaler

	BCA *gdbc.Adapter

	// Protocol IDs for breathcast and wingspan.
	BCID, WSID byte
}

// streamAccepter handles accepting individual streams for a single connection.
//
// Upon accepting a stream, if the protocol ID matches the ID for
// block propagation or vote gossip, it is directly associated with
// the corresponding protocol object.
// Otherwise, the value is sent on the provided accepted stream channel.
type streamAccepter struct {
	Conn dconn.Conn

	// TODO: most of the cases where we close the stream accepter,
	// we should also be closing the stream or perhaps even the underlying connection.
	Cancel context.CancelCauseFunc

	b *streamAccepterBase
}

func (a *streamAccepter) AcceptStreams(
	ctx context.Context,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for {
		s, err := a.Conn.QUIC.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				// Assume context cancellation was the cause of the failed accept.
				// If it wasn't the cause and we just raced with context cancellation,
				// it should be fine.
				return
			}

			a.Cancel(fmt.Errorf("failed to accept stream: %w", err))
			return
		}

		if err := s.SetReadDeadline(time.Now().Add(readProtocolIDTimeout)); err != nil {
			a.Cancel(fmt.Errorf("failed to set read deadline before reading protocol ID: %w", err))
			return
		}
		var protocolID [1]byte
		if _, err := io.ReadFull(s, protocolID[:]); err != nil {
			a.Cancel(fmt.Errorf("failed to read protocol ID from full stream: %w", err))
			return
		}

		if protocolID[0] == a.b.BCID {
			a.handleBreathcastStream(ctx, s)
			continue
		}

		// Otherwise, pass the stream to the application.
		as := AcceptedStream{
			Conn:       a.Conn,
			Stream:     s,
			ProtocolID: protocolID[0],
		}
		select {
		case <-ctx.Done():
			return
		case a.b.AcceptedStreamCh <- as:
			// Okay.
		}
	}
}

func (a *streamAccepter) handleBreathcastStream(
	ctx context.Context,
	s quic.Stream,
) {
	// We've parsed only the protocol ID so far.
	// Still working from the earlier read deadline before parsing the ID.
	bid, err := a.b.BCA.ExtractStreamBroadcastID(s, nil)
	if err != nil {
		a.Cancel(fmt.Errorf(
			"failed to extract stream broadcast ID: %w", err,
		))
		return
	}

	ah, _, err := breathcast.ExtractStreamApplicationHeader(s, nil)
	if err != nil {
		a.Cancel(fmt.Errorf(
			"failed to extract stream application header: %w", err,
		))
		return
	}

	// Now that we've extracted the broadcast ID and application header,
	// we can run the quick check via the network adapter.
	respCh := make(chan breathcastCheckResult, 1)
	check := breathcastCheck{
		BroadcastID: bid,
		AppHeader:   ah,

		CheckResult: respCh,
	}
	select {
	case <-ctx.Done():
		// Probably unnecessary to cancel, but won't hurt.
		a.Cancel(fmt.Errorf(
			"context canceled while doing breathcast check: %w", context.Cause(ctx),
		))
		return
	case a.b.BreathcastCheck <- check:
		// Okay.
	}

	var result breathcastCheckResult
	select {
	case <-ctx.Done():
		// Probably unnecessary to cancel, but won't hurt.
		a.Cancel(fmt.Errorf(
			"context canceled while awaiting breathcast check result: %w", context.Cause(ctx),
		))
		return
	case result = <-respCh:
		// Okay.
	}

	switch result {
	case breathcastCheckRejected:
		// Just cancel the worker for now.
		a.Cancel(errors.New(
			"rejected by network adapter",
		))
		return
	case breathcastCheckAccepted:
		// The NetworkAdapter handled the stream, so we are done in this handler.
		return
	case breathcastCheckNeedsProcessed:
		// Continue past the switch.
		break
	default:
		panic(fmt.Errorf(
			"BUG: unhandled breathcast check result %d", result,
		))
	}

	// The application header was the fully serialized proposed header.
	var ph tmconsensus.ProposedHeader
	if err := a.b.Unmarshaler.UnmarshalProposedHeader(ah, &ph); err != nil {
		a.Cancel(fmt.Errorf(
			"failed to parse proposed header from application header: %w", err,
		))
		return
	}

	// TODO: how do we extract the OriginationDetails from the proposed header?

	panic(errors.New(
		"TODO: finish parsing proposed header and send back to NetworkAdapter",
	))

	// TODO: pass some details back to the adapter,
	// which will inspect the live sessions
	// and then add this stream to an existing session
	// or pass it to the mirror to decide whether a new session is warranted.
}

func (a *streamAccepter) AcceptUniStreams(
	ctx context.Context,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for {
		s, err := a.Conn.QUIC.AcceptUniStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				// Assume context cancellation was the cause of the failed accept.
				// If it wasn't the cause and we just raced with context cancellation,
				// it should be fine.
				return
			}

			a.Cancel(fmt.Errorf("failed to accept uni stream: %w", err))
			return
		}

		if err := s.SetReadDeadline(time.Now().Add(readProtocolIDTimeout)); err != nil {
			a.Cancel(fmt.Errorf("failed to set read deadline before reading protocol ID: %w", err))
			return
		}
		var protocolID [1]byte
		if _, err := io.ReadFull(s, protocolID[:]); err != nil {
			a.Cancel(fmt.Errorf("failed to read protocol ID from uni stream: %w", err))
			return
		}

		if protocolID[0] == a.b.WSID {
			a.handleWingspanStream(ctx, s)
			continue
		}

		// Otherwise, pass the stream to the application.
		as := AcceptedUniStream{
			Conn:       a.Conn,
			Stream:     s,
			ProtocolID: protocolID[0],
		}
		select {
		case <-ctx.Done():
			return
		case a.b.AcceptedUniStreamCh <- as:
			// Okay.
		}
	}
}

func (a *streamAccepter) handleWingspanStream(
	ctx context.Context,
	s quic.ReceiveStream,
) {
	panic("TODO")
}
