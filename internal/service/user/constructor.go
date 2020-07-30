package user

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/service"
	"go.uber.org/fx"
)

type ServiceParams struct {
	fx.In

	ApplicationService service.ApplicationService
	UserRepo           repository.UserRepository
	//userIdentityRepo repository.UserIdentityRepository
}

func New(params ServiceParams) service.UserService {
	return &Service{
		params,
	}
}
