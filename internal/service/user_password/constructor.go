package user_password

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/service"
	"go.uber.org/fx"
)

type ServiceParams struct {
	fx.In

	ApplicationService  service.ApplicationService
	UserIdentityService service.UserIdentityService
}

func New(params ServiceParams) service.UserPasswordService {
	return &Service{
		params,
	}
}
