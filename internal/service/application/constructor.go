package application

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/service"
	"go.uber.org/fx"
)

type ServiceParams struct {
	fx.In

	ApplicationRepo repository.ApplicationRepository
}

func New(params ServiceParams) service.ApplicationService {
	return &Service{
		params,
	}
}
