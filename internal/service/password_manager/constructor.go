package password_manager

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/service"
	"go.uber.org/fx"
)

type ServiceParams struct {
	fx.In

	Users          repository.UserRepository
	Spaces         repository.SpaceRepository
	UserIdentities repository.UserIdentityRepository
}

func New(params ServiceParams) service.PasswordManager {
	return &Service{
		params,
	}
}
