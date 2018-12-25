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
	cfg     *config.Config
	logger  *logrus.Entry
	cfgFile string
	command = &cobra.Command{}
)

func Execute() {
	if err := command.Execute(); err != nil {
		logger.Fatal(err)
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	command.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is $HOME/config.example.yaml)")
}

func initConfig() {
	var err error

	cfg, err = config.LoadConfig(cfgFile)
	if err != nil {
		log.Fatal("Failed to load config: " + err.Error())
	}

	logger, err = config.ConfigureLogging(&cfg.Logger)
	if err != nil {
		log.Fatal("Failed to configure logging: " + err.Error())
	}

	logger.Debug("Config accepted")
}
