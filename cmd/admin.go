package cmd

import (
	// "github.com/ProtocolONE/auth1.protocol.one/internal/admin"
	// "github.com/ProtocolONE/auth1.protocol.one/internal/app"
	"github.com/ProtocolONE/auth1.protocol.one/internal/admin"
	"github.com/ProtocolONE/auth1.protocol.one/internal/app/container/env"
	"github.com/ProtocolONE/auth1.protocol.one/internal/app/container/repository"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Start AuthOne administration server",
	RunE:  runAdminServer,
}

func runAdminServer(cmd *cobra.Command, args []string) error {
	var cfg config.Admin
	if err := config.Load(&cfg); err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}

	db := createDatabase(&cfg.Database)
	defer db.Close()

	app := fx.New(
		env.New(),
		env.NewDB(db.DB(""))(),
		repository.New(),
		fx.Provide(
			admin.NewServer,
			admin.NewSpaceHandler,
			admin.NewProvidersHandler,
		),
		fx.Invoke(func(s *admin.Server) {
			//
		}),
	)

	app.Run()

	return nil

	// app, err := app.New(db.DB(""))
	// if err != nil {
	// 	zap.L().Fatal("Cannot create app", zap.Error(err))
	// }
	// err = app.Init()
	// if err != nil {
	// 	zap.L().Fatal("Cannot init app", zap.Error(err))
	// }

	// s := admin.NewServer()

	// return s.Serve(":8080")
}
