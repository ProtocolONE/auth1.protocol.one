package cmd

import (
	"auth-one-api/pkg/api"
	"github.com/spf13/cobra"
)

var sCommand = &cobra.Command{
	Use:   "server",
	Short: "Run AuthOne api server with given configuration",
	Run:   runServer,
}

func init() {
	mCommand.AddCommand(sCommand)
}

func runServer(cmd *cobra.Command, args []string) {
	serverConfig := api.ServerConfig{
		Log:          logger,
		Jwt:          &cfg.Jwt,
		ServerConfig: &cfg.Server,
	}

	server, err := api.NewServer(&serverConfig)
	if err != nil {
		logger.Fatal("Failed to create server: " + err.Error())
	}

	logger.Infof("Starting up server")

	err = server.Start()
	if err != nil {
		logger.Fatal("Failed to start server: " + err.Error())
	}
}
