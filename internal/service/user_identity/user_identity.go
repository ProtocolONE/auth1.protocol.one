package user_identity

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

type Service struct {
	ServiceParams
}

func (s Service) GetUserIdentities(ctx context.Context, appID, userID string) ([]*entity.UserIdentity, error) {
	ids, err := s.UserIdentityRepo.FindIdentities(ctx, appID, userID)
	if err != nil {
		return nil, err
	}
	return ids, nil
}
