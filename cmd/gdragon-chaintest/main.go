package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"

	petname "github.com/dustinkirkland/golang-petname"
	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/gordian-engine/gdragon/cmd/gdragon-chaintest/internal"
	"github.com/gordian-engine/gdragon/cmd/gdragon-chaintest/internal/dataless"
	"github.com/spf13/cobra"
)

func main() {
	if err := mainE(); err != nil {
		os.Exit(1)
	}
}

func mainE() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	root := NewRootCmd(logger)
	if err := root.ExecuteContext(ctx); err != nil {
		logger.Error("Failure", "err", err)
		os.Stderr.Sync()
		return err
	}

	return nil
}

func NewRootCmd(log *slog.Logger) *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "gdragon-chaintest SUBCOMMAND",

		Long: `gdragon-chaintest is used for orchestration of local chains for testing gdragon
(that is, the interaction between gdragon, dragon, and gordian).

The user provides a single configuration file describing the network,
and the tooling ensures all the described participants are started as independent processes.
`,
	}

	rootCmd.AddCommand(
		newCoordCmd(log),
		newValCmd(log),
	)

	return rootCmd
}

func newCoordCmd(log *slog.Logger) *cobra.Command {
	coordCmd := &cobra.Command{
		Use: "coord",

		Short: "Commands to run or interact with the coordinator service",
	}

	coordCmd.AddCommand(
		newCoordServeCmd(log),
		newCoordStartCmd(log),
	)

	return coordCmd
}

func newCoordServeCmd(log *slog.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use: "serve [PATH_TO_SOCKET_FILE=/var/run/gdct.$RANDOM_WORDS.$PID.sock]",

		Short: "Run the coordinator service for the nodes in the chain test",

		Args: cobra.RangeArgs(0, 1),

		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			var socketPath string
			if len(args) == 0 {
				randName := petname.Generate(2, "-")

				socketPath = fmt.Sprintf("/var/run/gdct.%s.%d.sock", randName, os.Getpid())
			} else {
				socketPath = args[0]
			}

			ln, err := new(net.ListenConfig).Listen(ctx, "unix", socketPath)
			if err != nil {
				return fmt.Errorf("failed to listen: %w", err)
			}
			log.Info("Started coordinator socket listener", "path", socketPath)

			c := internal.NewCoordinator(
				log.With("sys", "coord"),
			)

			c.Serve(ctx, ln)
			c.Wait()

			return nil
		},
	}

	return cmd
}

func newCoordStartCmd(log *slog.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use: "start PATH_TO_SOCKET_FILE",

		Short: "Tell the coordinator service on the given socket file to start running the chain",

		Args: cobra.ExactArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			cc := internal.NewCoordinatorClient(args[0])

			if err := cc.Start(ctx); err != nil {
				return fmt.Errorf("sending start command: %w", err)
			}

			return nil
		},
	}

	return cmd
}

func newValCmd(log *slog.Logger) *cobra.Command {
	valCmd := &cobra.Command{
		Use: "val",

		Short: "Run a particular application's validator",
	}

	valCmd.AddCommand(
		newValDatalessCmd(log),
	)

	return valCmd
}

func newValDatalessCmd(log *slog.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use: "dataless VAL_SHARED_HOME_DIR PATH_TO_SOCKET_FILE",

		Short: "Run a validator for the dataless chain",

		Args: cobra.ExactArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			pubKey, privKey, err := ed25519.GenerateKey(nil)
			if err != nil {
				return fmt.Errorf("generating key: %w", err)
			}

			ca, err := dcerttest.GenerateCA(dcerttest.FastConfig())
			if err != nil {
				return fmt.Errorf("generating CA: %w", err)
			}

			leaf, err := ca.CreateLeafCert(dcerttest.LeafConfig{
				DNSNames: []string{"localhost"},
			})
			if err != nil {
				return fmt.Errorf("generating leaf certificate: %w", err)
			}

			udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
				IP: net.IPv4(127, 0, 0, 1),
				// Use ephemeral port.
			})
			if err != nil {
				return fmt.Errorf("UDP listener: %w", err)
			}

			cc := internal.NewCoordinatorClient(args[1])

			if err := cc.Register(ctx, pubKey, udpConn.LocalAddr().String(), ca.Cert); err != nil {
				return fmt.Errorf("failed to register public key: %w", err)
			}

			homeDir := filepath.Join(args[0], fmt.Sprintf("%x", pubKey))
			if err := os.MkdirAll(homeDir, 0700); err != nil {
				return fmt.Errorf("making validator home directory: %w", err)
			}
			log.Info("Registered public key", "key", fmt.Sprintf("%x", pubKey), "home_dir", homeDir)

			g, err := cc.AwaitGenesis(ctx)
			if err != nil {
				return fmt.Errorf("failed to await genesis: %w", err)
			}

			peers := make([]dataless.Peer, 0, len(g.Validators))
			cas := make([]*x509.Certificate, 0, len(g.Validators))
			for _, v := range g.Validators {
				peers = append(peers, dataless.Peer{
					PubKey: v.Ed25519PubKey,
					Addr:   v.ListenAddr,
				})
				cas = append(cas, v.CACert)
			}

			cfg := dataless.ValidatorConfig{
				Log: log,

				TrustedCAs: cas,

				Peers: peers,

				PubKey:  pubKey,
				PrivKey: privKey,

				UDPConn: udpConn,

				P2PCert:        leaf.Cert,
				P2PCertPrivKey: leaf.PrivKey,
			}

			if err := dataless.RunValidator(ctx, cfg); err != nil {
				return fmt.Errorf("failed to run validator: %w", err)
			}

			return nil
		},
	}
	return cmd
}
