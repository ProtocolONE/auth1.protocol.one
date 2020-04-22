package service

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

type UserIdentityService interface {
	GetUserIdentities(ctx context.Context, appID, userID string) ([]*entity.UserIdentity, error)
}
