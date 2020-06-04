package handler

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/service"
	"go.uber.org/fx"
)

type Params struct {
	fx.In

	ProfileService      service.ProfileService
	UserIdentityService service.UserIdentityService
	PasswordManager     service.PasswordManager
	// ApplicationService  service.ApplicationService
	Users  repository.UserRepository
	Spaces repository.SpaceRepository
}

func New(params Params) *Handler {
	return &Handler{
		profile:         params.ProfileService,
		Users:           params.Users,
		Spaces:          params.Spaces,
		userIdentity:    params.UserIdentityService,
		passwordManager: params.PasswordManager,
		// app:             params.ApplicationService,
	}
}
