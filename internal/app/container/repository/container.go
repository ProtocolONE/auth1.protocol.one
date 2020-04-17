package repository

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/repository/profile"
	"github.com/ProtocolONE/auth1.protocol.one/internal/repository/user"
	"go.uber.org/fx"
)

func New() fx.Option {
	return fx.Provide(
		profile.New,
		user.New,
	)
}
