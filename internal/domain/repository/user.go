package repository

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

//go:generate mockgen -destination=../mocks/user_repository.go -package=mocks github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository UserRepository
type UserRepository interface {
	SetPassword(ctx context.Context, i *entity.User) error

	FindByID(ctx context.Context, id string) (*entity.User, error)
}
