package service

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

type UserIdentityService interface {
	UpdateCredential(ctx context.Context, data *UpdateUserIdentityCredentialData) error

	GetByID(ctx context.Context, id string) (*entity.UserIdentity, error)
	GetIdentity(ctx context.Context, data *GetIdentityData) (*entity.UserIdentity, error)
	GetIdentities(ctx context.Context, appID, userID string) ([]*entity.UserIdentity, error)
}

type GetIdentityData struct {
	AppID              string
	IdentityProviderID string
	UserID             string
}

type UpdateUserIdentityCredentialData struct {
	ID         string
	Credential *string
}
