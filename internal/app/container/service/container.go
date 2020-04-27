package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/service/application"
	"github.com/ProtocolONE/auth1.protocol.one/internal/service/profile"
	"github.com/ProtocolONE/auth1.protocol.one/internal/service/user"
	"github.com/ProtocolONE/auth1.protocol.one/internal/service/user_identity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/service/user_password"
	"go.uber.org/fx"
)

func New() fx.Option {
	return fx.Provide(
		application.New,
		profile.New,
		user.New,
		user_identity.New,
		user_password.New,
	)
}
