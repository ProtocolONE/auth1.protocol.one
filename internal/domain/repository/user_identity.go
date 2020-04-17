package repository

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

type UserIdentityRepository interface {
	GetSocialProfiles(ctx context.Context, userID string) ([]*entity.SocialProfile, error)
}
