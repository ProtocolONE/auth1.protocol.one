package repository

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

//go:generate mockgen -destination=../mocks/profile_repository.go -package=mocks github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository ProfileRepository
type ProfileRepository interface {
	Create(ctx context.Context, i *entity.Profile) error
	Update(ctx context.Context, i *entity.Profile) error

	FindByID(ctx context.Context, id string) (*entity.Profile, error)
	FindByUserID(ctx context.Context, userID string) (*entity.Profile, error)
}
