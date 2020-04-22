package service

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

type ApplicationService interface {
	GetByID(ctx context.Context, id string) (*entity.Application, error)
}
