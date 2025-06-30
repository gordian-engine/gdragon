package gdtmp2p

import (
	"context"
	"io"
	"log/slog"
	"sync"

	"github.com/quic-go/quic-go"
)

type connWorker struct {
	log *slog.Logger

	Cancel context.CancelFunc

	incomingStreams    chan<- incomingStream
	incomingUniStreams chan<- incomingUniStream

	wg sync.WaitGroup
}

func (w *connWorker) Run(
	ctx context.Context,
	// TODO: parentWG
	conn quic.Connection,
) {
	w.wg.Add(2)

	go w.acceptB(ctx, conn)
	go w.acceptU(ctx, conn)
}

func (w *connWorker) acceptB(ctx context.Context, conn quic.Connection) {
	defer w.wg.Done()

	var buf [1]byte
	for {
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			// Assume connection is bad.
			// TODO: do we need to signal this upwards to force a disconnect?
			w.log.Info("Failed to accept stream", "err", err)
			return
		}

		// Assume we can do a non-blocking read of the first byte,
		// given that the stream is not observable until something is written.
		if _, err := io.ReadFull(s, buf[:]); err != nil {
			w.log.Info("Failed to read protocol ID", "err", err)
			return
		}

		select {
		case <-ctx.Done():
			return
		case w.incomingStreams <- incomingStream{
			ProtocolID: buf[0],
			Stream:     s,
		}:
			// Okay.
		}
	}
}

func (w *connWorker) acceptU(ctx context.Context, conn quic.Connection) {
	defer w.wg.Done()

	var buf [1]byte
	for {
		s, err := conn.AcceptUniStream(ctx)
		if err != nil {
			// Assume connection is bad.
			// TODO: do we need to signal this upwards to force a disconnect?
			w.log.Info("Failed to accept unidirectional stream", "err", err)
			return
		}

		// Assume we can do a non-blocking read of the first byte,
		// given that the stream is not observable until something is written.
		if _, err := io.ReadFull(s, buf[:]); err != nil {
			w.log.Info("Failed to read protocol ID from unidirectional stream", "err", err)
			return
		}

		select {
		case <-ctx.Done():
			return
		case w.incomingUniStreams <- incomingUniStream{
			ProtocolID: buf[0],
			Stream:     s,
		}:
			// Okay.
		}
	}
}
