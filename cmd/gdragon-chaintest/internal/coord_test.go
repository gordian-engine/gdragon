package internal_test

import (
	"context"
	"crypto/ed25519"
	"net"
	"os"
	"testing"
	"time"

	"github.com/gordian-engine/dragon/dcert/dcerttest"
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

	ca1, err := dcerttest.GenerateCA(dcerttest.FastConfig())
	require.NoError(t, err)
	pub1, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NoError(t, client.Register(ctx, pub1, "example.com:1111", ca1.Cert))

	ca2, err := dcerttest.GenerateCA(dcerttest.FastConfig())
	require.NoError(t, err)
	pub2, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NoError(t, client.Register(ctx, pub2, "example.com:2222", ca2.Cert))

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

	require.Len(t, gen.Validators, 2)
	require.Equal(t, pub1, gen.Validators[0].Ed25519PubKey)
	require.Equal(t, "example.com:1111", gen.Validators[0].ListenAddr)
	require.True(t, ca1.Cert.Equal(gen.Validators[0].CACert))
	require.Equal(t, pub2, gen.Validators[1].Ed25519PubKey)
	require.Equal(t, "example.com:2222", gen.Validators[1].ListenAddr)
	require.True(t, ca2.Cert.Equal(gen.Validators[1].CACert))
}
