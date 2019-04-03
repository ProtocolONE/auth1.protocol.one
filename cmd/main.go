package cmd

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"os"
)

var (
	cfg     *config.Config
	logger  *zap.Logger
	command = &cobra.Command{}
)

func Execute() {
	var err error

	logger, _ = zap.NewProduction()
	zap.ReplaceGlobals(logger)
	defer logger.Sync() // flushes buffer, if any

	cfg, err = config.Load()
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}

	if err := command.Execute(); err != nil {
		logger.Fatal("Command execution failed with error", zap.Error(err))
		os.Exit(1)
	}
}
