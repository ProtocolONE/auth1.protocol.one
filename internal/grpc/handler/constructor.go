package handler

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/service"
	"go.uber.org/fx"
)

type Params struct {
	fx.In

	ProfileService      service.ProfileService
	UserService         service.UserService
	UserIdentityService service.UserIdentityService
	PasswordManager     service.PasswordManager
	// ApplicationService  service.ApplicationService
	Users  repository.UserRepository
	Spaces repository.SpaceRepository
}

func New(params Params) *Handler {
	return &Handler{
		ProfileService:      params.ProfileService,
		UserService:         params.UserService,
		Users:               params.Users,
		Spaces:              params.Spaces,
		userIdentityService: params.UserIdentityService,
		passwordManager:     params.PasswordManager,
		// app:             params.ApplicationService,
	}
}
