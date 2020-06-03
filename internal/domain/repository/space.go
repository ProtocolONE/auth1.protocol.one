package repository

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

type SpaceRepository interface {
	Create(ctx context.Context, space *entity.Space) error
	Update(ctx context.Context, space *entity.Space) error

	Find(ctx context.Context) ([]*entity.Space, error)
	FindByID(ctx context.Context, id entity.SpaceID) (*entity.Space, error)
}
