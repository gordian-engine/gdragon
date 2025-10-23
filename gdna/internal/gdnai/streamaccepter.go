package gdnai

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/gdragon/gdbc"
	"github.com/gordian-engine/gordian/tm/tmcodec"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
)

const readProtocolIDTimeout = 50 * time.Millisecond

// AcceptedStream is a value used for the accepted stream channel
// provided to [NetworkAdapterConfig], for the application to consume.
type AcceptedStream struct {
	Conn   dconn.Conn
	Stream dquic.Stream

	ProtocolID byte
}

// AcceptedUniStream is a value used for the accepted unidirectional stream channel
// provided to [NetworkAdapterConfig], for the application to consume.
type AcceptedUniStream struct {
	Conn   dconn.Conn
	Stream dquic.ReceiveStream

	ProtocolID byte
}

// StreamAccepterBase contains the unchanging base values for a [StreamAccepter].
type StreamAccepterBase struct {
	AcceptedStreamCh    chan<- AcceptedStream
	AcceptedUniStreamCh chan<- AcceptedUniStream

	IncomingHeaders     chan<- IncomingHeader
	BreathcastDatagrams chan<- BreathcastDatagram

	IncomingDatagrams chan<- IncomingDatagram

	// The streamAccepter instances send on this channel,
	// and the NetworkAdapter receives on it.
	BreathcastChecks chan BreathcastCheck

	Unmarshaler tmcodec.Unmarshaler

	// How to extract the broadcast details from the proposed header's
	// annotations set by the driver.
	GetBroadcastDetails func(driverAnnotation []byte) (gdbc.BroadcastDetails, error)

	BCA *gdbc.Adapter

	// Protocol IDs for breathcast and wingspan.
	BCID, WSID byte
}

// StreamAccepter handles accepting individual streams for a single connection.
//
// Upon accepting a stream, if the protocol ID matches the ID for
// block propagation or vote gossip, it is directly associated with
// the corresponding protocol object.
// Otherwise, the value is sent on the provided accepted stream channel.
type StreamAccepter struct {
	conn dconn.Conn

	// TODO: most of the cases where we close the stream accepter,
	// we should also be closing the stream or perhaps even the underlying connection.
	cancel context.CancelCauseFunc

	b *StreamAccepterBase
}

func NewStreamAccepter(
	conn dconn.Conn,
	cancel context.CancelCauseFunc,
	base *StreamAccepterBase,
) *StreamAccepter {
	return &StreamAccepter{
		conn:   conn,
		cancel: cancel,
		b:      base,
	}
}

// Cancel ends a's underlying goroutines that accept QUIC streams.
func (a *StreamAccepter) Cancel(e error) {
	// TODO: this may need to be aware of an active stream as well.
	a.cancel(e)
}

func (a *StreamAccepter) AcceptStreams(
	ctx context.Context,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for {
		s, err := a.conn.QUIC.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				// Assume context cancellation was the cause of the failed accept.
				// If it wasn't the cause and we just raced with context cancellation,
				// it should be fine.
				return
			}

			a.cancel(fmt.Errorf("failed to accept stream: %w", err))
			return
		}

		if err := s.SetReadDeadline(time.Now().Add(readProtocolIDTimeout)); err != nil {
			a.cancel(fmt.Errorf("failed to set read deadline before reading protocol ID: %w", err))
			return
		}
		var protocolID [1]byte
		if _, err := io.ReadFull(s, protocolID[:]); err != nil {
			a.cancel(fmt.Errorf("failed to read protocol ID from full stream: %w", err))
			return
		}

		if protocolID[0] == a.b.BCID {
			a.handleBreathcastStream(ctx, s)
			continue
		}

		// Otherwise, pass the stream to the application.
		as := AcceptedStream{
			Conn:       a.conn,
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

func (a *StreamAccepter) handleBreathcastStream(
	ctx context.Context,
	s dquic.Stream,
) {
	// We've parsed only the protocol ID so far.
	// Still working from the earlier read deadline before parsing the ID.
	bidBytes, err := a.b.BCA.ExtractStreamBroadcastID(s, nil)
	if err != nil {
		a.cancel(fmt.Errorf(
			"failed to extract stream broadcast ID: %w", err,
		))
		return
	}

	var bid gdbc.BroadcastID
	if err := bid.Parse(bidBytes); err != nil {
		panic(fmt.Errorf(
			"BUG: should be impossible to fail parsing a BroadcastID after extraction: %w",
			err,
		))
	}

	ah, _, err := breathcast.ExtractStreamApplicationHeader(s, nil)
	if err != nil {
		a.cancel(fmt.Errorf(
			"failed to extract stream application header: %w", err,
		))
		return
	}

	// Now that we've extracted the broadcast ID and application header,
	// we can run the quick check via the network adapter.
	respCh := make(chan BreathcastCheckResult, 1)
	check := BreathcastCheck{
		BroadcastID: bid,
		AppHeader:   ah,

		CheckResult: respCh,
	}
	select {
	case <-ctx.Done():
		// Probably unnecessary to cancel, but won't hurt.
		a.cancel(fmt.Errorf(
			"context canceled while doing breathcast check: %w", context.Cause(ctx),
		))
		return
	case a.b.BreathcastChecks <- check:
		// Okay.
	}

	var result BreathcastCheckResult
	select {
	case <-ctx.Done():
		// Probably unnecessary to cancel, but won't hurt.
		a.cancel(fmt.Errorf(
			"context canceled while awaiting breathcast check result: %w", context.Cause(ctx),
		))
		return
	case result = <-respCh:
		// Okay.
	}

	switch result {
	case BreathcastCheckRejected:
		// Just cancel the worker for now.
		a.cancel(errors.New(
			"rejected by network adapter",
		))
		return
	case BreathcastCheckAccepted:
		// The NetworkAdapter handled the stream, so we are done in this handler.
		return
	case BreathcastCheckNeedsProcessed:
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
		a.cancel(fmt.Errorf(
			"failed to parse proposed header from application header: %w", err,
		))
		return
	}

	bd, err := a.b.GetBroadcastDetails(ph.Annotations.Driver)
	if err != nil {
		a.cancel(fmt.Errorf(
			"failed to extract broadcast details from driver annotations: %w", err,
		))
		return
	}

	// Fully parsed, so send it back to the core network adapter.
	ih := IncomingHeader{
		Conn:             a.conn,
		Stream:           s,
		BroadcastID:      bid,
		AppHeaderBytes:   ah,
		ProposedHeader:   ph,
		BroadcastDetails: bd,
	}

	select {
	case <-ctx.Done():
		a.cancel(fmt.Errorf(
			"context canceled while sending incoming header: %w", context.Cause(ctx),
		))
		return
	case a.b.IncomingHeaders <- ih:
		// Okay.
	}

	// Once handed off to the network adapter,
	// the stream accepter no longer owns the stream.
}

// IncomingHeader is the type sent from the [StreamAccepter]
// back to the NetworkAdapter,
// after a [BreathcastCheck] indicated it needed further processing.
type IncomingHeader struct {
	Conn   dconn.Conn
	Stream dquic.Stream

	BroadcastID gdbc.BroadcastID

	AppHeaderBytes []byte
	ProposedHeader tmconsensus.ProposedHeader

	BroadcastDetails gdbc.BroadcastDetails
}

func (a *StreamAccepter) ReceiveDatagrams(
	ctx context.Context,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

LOOP:
	for {
		d, err := a.conn.QUIC.ReceiveDatagram(ctx)
		if err != nil {
			// It looks as though receive datagram can only return an error
			// for a context cancellation or for the connection being closed.
			// It doesn't appear that we need to distinguish them.
			a.cancel(fmt.Errorf("error receiving datagram: %w", err))
			return
		}

		if len(d) == 0 {
			a.cancel(errors.New("received empty datagram"))
			return
		}

		if d[0] == a.b.BCID {
			// Just extract the broadcast ID
			// and forward the datagram to the network adapter.
			var bid gdbc.BroadcastID
			if err := bid.Parse(d[1:]); err != nil {
				a.cancel(fmt.Errorf(
					"malformed broadcast ID in breathcast datagram: %w", err,
				))
				return
			}

			select {
			case <-ctx.Done():
				return

			case a.b.BreathcastDatagrams <- BreathcastDatagram{
				Conn:     a.conn,
				BID:      bid,
				Datagram: d,
			}:
				continue LOOP
			}
		}

		// Otherwise it was an application-level datagram.
		// Don't process it at all; just raise it to the application.
		select {
		case <-ctx.Done():
			return
		case a.b.IncomingDatagrams <- IncomingDatagram{
			Conn:     a.conn,
			Datagram: d,
		}:
			// This datagram has been handed off.
		}
	}
}

// BreathcastDatagram is a partially parsed datagram
// that is confirmed to belong the breathcast protocol
// and that has a properly extracted broadcast ID.
type BreathcastDatagram struct {
	Conn dconn.Conn

	BID gdbc.BroadcastID

	Datagram []byte
}

// IncomingDatagram is an application-layer datagram.
// The stream accepters send these values on the provided channel in [StreamAdapterBase].
type IncomingDatagram struct {
	Conn dconn.Conn

	Datagram []byte
}

func (a *StreamAccepter) AcceptUniStreams(
	ctx context.Context,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for {
		s, err := a.conn.QUIC.AcceptUniStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				// Assume context cancellation was the cause of the failed accept.
				// If it wasn't the cause and we just raced with context cancellation,
				// it should be fine.
				return
			}

			a.cancel(fmt.Errorf("failed to accept uni stream: %w", err))
			return
		}

		if err := s.SetReadDeadline(time.Now().Add(readProtocolIDTimeout)); err != nil {
			a.cancel(fmt.Errorf("failed to set read deadline before reading protocol ID: %w", err))
			return
		}
		var protocolID [1]byte
		if _, err := io.ReadFull(s, protocolID[:]); err != nil {
			a.cancel(fmt.Errorf("failed to read protocol ID from uni stream: %w", err))
			return
		}

		if protocolID[0] == a.b.WSID {
			a.handleWingspanStream(ctx, s)
			continue
		}

		// Otherwise, pass the stream to the application.
		as := AcceptedUniStream{
			Conn:       a.conn,
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

func (a *StreamAccepter) handleWingspanStream(
	ctx context.Context,
	s dquic.ReceiveStream,
) {
	// TODO: these streams are created immediately upon round activation,
	// so we need to create and manage the stream here even if tests are exercising them yet.
}
