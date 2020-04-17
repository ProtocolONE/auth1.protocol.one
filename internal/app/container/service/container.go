package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/service/profile"
	"github.com/ProtocolONE/auth1.protocol.one/internal/service/user"
	"go.uber.org/fx"
)

func New() fx.Option {
	return fx.Provide(
		profile.New,
		user.New,
	)
}
