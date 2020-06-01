package app

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/app/container/env"
	"github.com/ProtocolONE/auth1.protocol.one/internal/app/container/handler"
	"github.com/ProtocolONE/auth1.protocol.one/internal/app/container/repository"
	"github.com/ProtocolONE/auth1.protocol.one/internal/app/container/service"
	"github.com/ProtocolONE/auth1.protocol.one/internal/grpc"
	"github.com/globalsign/mgo"
	"go.uber.org/fx"
)

type App struct {
	fxOptions fx.Option
	grpc      *grpc.Server
}

func New(db *mgo.Database) (*App, error) {
	var app = new(App)

	app.FxProvides(
		env.New,
		env.NewDB(db),
		handler.New,
		repository.New,
		service.New,
	)

	return app, nil
}

func (app *App) FxProvides(ff ...func() fx.Option) {
	options := make([]fx.Option, len(ff))
	for i, f := range ff {
		options[i] = f()
	}
	app.fxOptions = fx.Options(options...)
}

func (app *App) Init() error {
	app.fxOptions = fx.Options(
		app.fxOptions,
		fx.NopLogger,

		fx.Invoke(
			func(params grpc.Params) (*grpc.Server, error) {
				var err error
				app.grpc, err = grpc.NewServer(params)
				if err != nil {
					return nil, err
				}

				return app.grpc, nil
			},
		),
	)

	err := fx.New(app.fxOptions).Start(context.Background())
	if err != nil {
		return err
	}

	return nil
}

func (app *App) Run() error {
	return app.grpc.Run()
}
