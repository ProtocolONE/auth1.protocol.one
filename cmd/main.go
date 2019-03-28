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
	cfgFile string
	command = &cobra.Command{}
)

func Execute() {
	if err := command.Execute(); err != nil {
		logger.Fatal("Command execution failed with error", zap.Error(err))
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	command.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is $HOME/etc/config.yaml)")
}

func initConfig() {
	var err error

	logger, _ = zap.NewProduction()
	zap.ReplaceGlobals(logger)
	defer logger.Sync() // flushes buffer, if any

	cfg, err = config.LoadConfig(cfgFile)
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}

	logger.Info("Config accepted")
}
