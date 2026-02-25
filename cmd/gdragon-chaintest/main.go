package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"

	petname "github.com/dustinkirkland/golang-petname"
	"github.com/spf13/cobra"
	"github.com/gordian-engine/gdragon/cmd/gdragon-chaintest/internal"
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
