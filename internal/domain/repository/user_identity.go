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
	FindIdentity(ctx context.Context, appID, identityProviderID, userID string) (*entity.UserIdentity, error)
	FindIdentities(ctx context.Context, appID, userID string) ([]*entity.UserIdentity, error)
}
