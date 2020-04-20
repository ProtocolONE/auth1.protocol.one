package repository

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

type UserIdentityRepository interface {
	FindSocialProfile(ctx context.Context, userID, provider string) ([]*entity.SocialProfile, error)
	FindSocialProfiles(ctx context.Context, userID string) ([]*entity.SocialProfile, error)
}
