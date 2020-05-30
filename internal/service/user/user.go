package user

import (
	"context"
	"errors"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

type Service struct {
	ServiceParams
}

var ErrUserNotFound = errors.New("user not found")

func (s Service) GetByID(ctx context.Context, id entity.UserID) (*entity.User, error) {
	user, err := s.UserRepo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}
