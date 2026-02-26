package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"

	petname "github.com/dustinkirkland/golang-petname"
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
	cmd := &cobra.Command{
		Use: "coord [PATH_TO_SOCKET_FILE=/var/run/gdct.$RANDOM_WORDS.$PID.sock]",

		Short: "Run the coordinator for the nodes in the chain test",

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

func newValCmd(log *slog.Logger) *cobra.Command {
	valCmd := &cobra.Command{
		Use: "val",
	}

	valCmd.AddCommand(
		newValDatalessCmd(log),
	)

	return valCmd
}

func newValDatalessCmd(log *slog.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use: "dataless HOME_DIR PATH_TO_SOCKET_FILE",

		Short: "Run a validator for the dataless chain",

		Args: cobra.ExactArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			pubKey, privKey, err := ed25519.GenerateKey(nil)
			if err != nil {
				return fmt.Errorf("generating key: %w", err)
			}

			cc := internal.NewCoordinatorClient(args[1])

			if err := cc.Register(ctx, pubKey); err != nil {
				return fmt.Errorf("failed to register public key: %w", err)
			}

			log.Info("Registered public key", "key", fmt.Sprintf("%x", pubKey))

			g, err := cc.AwaitGenesis(ctx)
			if err != nil {
				return fmt.Errorf("failed to await genesis: %w", err)
			}

			if err := dataless.RunValidator(ctx, g.Ed25519PubKeys, privKey); err != nil {
				return fmt.Errorf("failed to run validator: %w", err)
			}

			return nil
		},
	}
	return cmd
}
