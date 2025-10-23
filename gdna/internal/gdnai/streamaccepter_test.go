package gdnai_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/gdragon/gdna/internal/gdnai"
	"github.com/stretchr/testify/require"
)

func TestStreamAccepter_datagramPassthrough(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)

	dCh := make(chan []byte, 4)
	sdr := stubDatagramReceiver{
		datagrams: dCh,
	}

	dc := dconn.Conn{
		QUIC: sdr,

		// The stream accepter doesn't use the chain;
		// it only passes it through back to the network adapter,
		// so we can leave it empty for test.
		Chain: dcert.Chain{},
	}

	incomingDatagramCh := make(chan gdnai.IncomingDatagram, 4)
	sa := gdnai.NewStreamAccepter(
		dc, cancel, &gdnai.StreamAccepterBase{
			BCID: 0xF0,

			IncomingDatagrams: incomingDatagramCh,
		},
	)

	var wg sync.WaitGroup
	wg.Add(1)

	go sa.ReceiveDatagrams(ctx, &wg)
	defer wg.Wait()
	defer cancel(nil)

	// No datagram available before send.
	select {
	case <-incomingDatagramCh:
		t.Fatal("data ready before send")
	default:
		// Good.
	}

	send := []byte("\xaatest")
	dCh <- send

	select {
	case d := <-incomingDatagramCh:
		require.Equal(t, gdnai.IncomingDatagram{
			Conn:     dc,
			Datagram: send,
		}, d)
		require.Equal(t, send, d.Datagram)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for datagram")
	}
}

type stubDatagramReceiver struct {
	// Embedded interface so we don't have to implement anything else.
	dquic.Conn

	datagrams <-chan []byte
}

func (r stubDatagramReceiver) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)

	case d := <-r.datagrams:
		return d, nil
	}
}
