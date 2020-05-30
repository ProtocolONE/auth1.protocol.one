package handler

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/service"
	"go.uber.org/fx"
)

type Params struct {
	fx.In

	ProfileService      service.ProfileService
	UserService         service.UserService
	UserIdentityService service.UserIdentityService
	PasswordManager     service.PasswordManager
	ApplicationService  service.ApplicationService
}

func New(params Params) *Handler {
	return &Handler{
		profile:         params.ProfileService,
		user:            params.UserService,
		userIdentity:    params.UserIdentityService,
		passwordManager: params.PasswordManager,
		app:             params.ApplicationService,
	}
}
