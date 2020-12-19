package service

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

type UserIdentityService interface {
	UpdateCredential(ctx context.Context, data *UpdateUserIdentityCredentialData) error

	GetByID(ctx context.Context, id entity.UserIdentityID) (*entity.UserIdentity, error)
	GetIdentity(ctx context.Context, pid entity.IdentityProviderID, uid entity.UserID) (*entity.UserIdentity, error)
	GetIdentities(ctx context.Context, userID entity.UserID) ([]*entity.UserIdentity, error)
}

type UpdateUserIdentityCredentialData struct {
	ID         string
	Credential string
}
