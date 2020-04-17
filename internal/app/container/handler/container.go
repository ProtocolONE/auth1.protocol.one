package handler

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/handler/grpc"
	"go.uber.org/fx"
)

func New() fx.Option {
	return fx.Provide(
		grpc.New,
	)
}
