package profile

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/service"
	"go.uber.org/fx"
)

type ServiceParams struct {
	fx.In

	ProfileRepo repository.ProfileRepository
}

func New(params ServiceParams) service.ProfileService {
	return &Service{
		params,
	}
}
