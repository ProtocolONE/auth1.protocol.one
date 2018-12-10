package cmd

import (
	"auth-one-api/pkg/config"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"log"
	"os"
)

var (
	cfg      *config.Config
	logger   *logrus.Entry
	cfgFile  string
	mCommand = &cobra.Command{
		Use:   "authone",
		Short: "Authenticate server by ProtocolOne",
		Long:  `Authenticate server by ProtocolOne`,
	}
)

func Execute() {
	if err := mCommand.Execute(); err != nil {
		logger.Fatal(err)
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	mCommand.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is $HOME/config.example.yaml)")
}

func initConfig() {
	var err error

	cfg, err = config.LoadConfig(cfgFile)
	if err != nil {
		log.Fatal("Failed to load config: " + err.Error())
	}

	logger, err = config.ConfigureLogging(&cfg.LogConfig)
	if err != nil {
		log.Fatal("Failed to configure logging: " + err.Error())
	}

	logger.Debugf("Config accepted")
}
