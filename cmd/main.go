package cmd

import (
	"os"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	cfg     *config.Config
	logger  *zap.Logger
	command = &cobra.Command{}
)

func Execute() {
	var err error

	if _, ok := os.LookupEnv("AUTHONE_LOGGING_DEV"); ok {
		logger, _ = zap.NewDevelopment()
	} else {
		logger, _ = zap.NewProduction()
	}
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
