package cmd

import (
	"os"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/appcore"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	cfg    *config.Config
	logger *zap.Logger
)

func Execute() {
	root := &cobra.Command{}
	// db migration
	root.AddCommand(migrationCmd)
	// user facing api server
	root.AddCommand(serverCmd)
	// administration server
	root.AddCommand(adminCmd)

	logger := appcore.InitLogger()
	defer logger.Sync() // flushes buffer, if any

	if err := root.Execute(); err != nil {
		logger.Fatal("Command execution failed with error", zap.Error(err))
		os.Exit(1)
	}
}
