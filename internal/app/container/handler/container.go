package handler

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/grpc"
	"github.com/ProtocolONE/auth1.protocol.one/internal/grpc/handler"
	"go.uber.org/fx"
)

func New() fx.Option {
	return fx.Provide(
		handler.New,
		grpc.NewServer,
	)
}
