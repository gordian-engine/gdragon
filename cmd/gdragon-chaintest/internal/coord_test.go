package internal_test

import (
	"context"
	"crypto/ed25519"
	"net"
	"os"
	"testing"
	"time"

	"github.com/gordian-engine/gdragon/cmd/gdragon-chaintest/internal"
	"github.com/neilotoole/slogt"
	"github.com/stretchr/testify/require"
)

// tempSocket returns a unix socket listener, and the filename
func tempSocket(t *testing.T) (string, net.Listener) {
	t.Helper()

	temp, err := os.CreateTemp("", "*.sock")
	require.NoError(t, err)
	temp.Close()
	socketPath := temp.Name()
	_ = os.Remove(socketPath)

	ln, err := new(net.ListenConfig).Listen(t.Context(), "unix", socketPath)
	require.NoError(t, err)

	t.Cleanup(func() { _ = ln.Close() })
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	return socketPath, ln
}

func TestCoordinator_registerAndGenesis(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	c := internal.NewCoordinator(slogt.New(t, slogt.Text()))
	defer c.Wait()
	defer cancel()

	socketPath, ln := tempSocket(t)
	c.Serve(ctx, ln)

	client := internal.NewCoordinatorClient(socketPath)

	pub1, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NoError(t, client.Register(ctx, pub1))

	pub2, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NoError(t, client.Register(ctx, pub2))

	genCh := make(chan internal.Genesis, 1)

	go func() {
		g, err := client.AwaitGenesis(ctx)
		require.NoError(t, err)
		genCh <- g
	}()

	require.NoError(t, client.Start(ctx))

	var gen internal.Genesis
	select {
	case gen = <-genCh:
		// Okay.
	case <-time.After(time.Second):
		t.Fatal("timed out awaiting genesis")
	}

	require.Equal(t, []ed25519.PublicKey{pub1, pub2}, gen.Ed25519PubKeys)
}
