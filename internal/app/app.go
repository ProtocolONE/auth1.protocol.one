package app

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/app/container/env"
	"github.com/ProtocolONE/auth1.protocol.one/internal/app/container/handler"
	"github.com/ProtocolONE/auth1.protocol.one/internal/app/container/repository"
	"github.com/ProtocolONE/auth1.protocol.one/internal/app/container/service"
	"github.com/ProtocolONE/auth1.protocol.one/internal/grpc"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/api"
	"github.com/globalsign/mgo"
	"go.uber.org/fx"
)

type App struct {
	grpc *grpc.Server
	app  *fx.App
}

func New(db *mgo.Database, srvConfig *api.ServerConfig) (*App, *api.Server, error) {
	var app = new(App)

	var server *api.Server

	app.app = fx.New(
		fx.NopLogger,

		env.New(),
		env.NewDB(db)(),
		handler.New(),
		repository.New(),
		service.New(),

		fx.Supply(srvConfig),
		fx.Provide(api.NewServer),

		fx.Populate(&app.grpc),
		fx.Populate(&server),
	)

	return app, server, nil
}

func (app *App) Init() error {
	err := app.app.Start(context.Background())
	if err != nil {
		return err
	}

	return nil
}

func (app *App) Run() error {
	return app.grpc.Run()
}
