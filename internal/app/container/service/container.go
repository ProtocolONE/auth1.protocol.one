package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/service/application"
	"github.com/ProtocolONE/auth1.protocol.one/internal/service/profile"
	"github.com/ProtocolONE/auth1.protocol.one/internal/service/user"
	"github.com/ProtocolONE/auth1.protocol.one/internal/service/user_identity"
	"go.uber.org/fx"
)

func New() fx.Option {
	return fx.Provide(
		profile.New,
		user.New,
		user_identity.New,
		application.New,
	)
}
