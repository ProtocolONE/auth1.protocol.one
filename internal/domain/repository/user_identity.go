package repository

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

const (
	UserIdentity_Password = "password"
	UserIdentity_Social   = "social"
)

//go:generate mockgen -destination=../mocks/user_identity_repository.go -package=mocks github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository UserIdentityRepository
type UserIdentityRepository interface {
	Update(ctx context.Context, i *entity.UserIdentity) error
	//
	FindByID(ctx context.Context, id entity.UserIdentityID) (*entity.UserIdentity, error)
	FindByProviderAndUser(ctx context.Context, idProviderID entity.IdentityProviderID, userID entity.UserID) (*entity.UserIdentity, error)
	FindForUser(ctx context.Context, userID entity.UserID) ([]*entity.UserIdentity, error)
}
