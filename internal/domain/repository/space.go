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
	FindForProvider(ctx context.Context, id entity.IdentityProviderID) (*entity.Space, error)
}

////////////////////////////////////////////////////////////////////////////////////
// Stubs, Fakes, Mocks
func OneSpaceRepo(s *entity.Space) SpaceRepository {
	return &oneSpaceRepository{s}
}

type oneSpaceRepository struct {
	space *entity.Space
}

func (r *oneSpaceRepository) Create(ctx context.Context, space *entity.Space) error { return nil }
func (r *oneSpaceRepository) Update(ctx context.Context, space *entity.Space) error { return nil }
func (r *oneSpaceRepository) Find(ctx context.Context) ([]*entity.Space, error)     { return nil, nil }
func (r *oneSpaceRepository) FindByID(ctx context.Context, id entity.SpaceID) (*entity.Space, error) {
	return r.space, nil
}
func (r *oneSpaceRepository) FindForProvider(ctx context.Context, id entity.IdentityProviderID) (*entity.Space, error) {
	return r.space, nil
}
