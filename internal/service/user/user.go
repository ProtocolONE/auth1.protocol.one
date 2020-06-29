package user

import (
	"context"
	"errors"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/service"
)

type Service struct {
	ServiceParams
}

var ErrUserNotFound = errors.New("user not found")

func (s Service) Update(ctx context.Context, data service.UpdateUserData) error {
	user, err := s.GetByID(ctx, data.ID)
	if err != nil {
		return err
	}

	if user == nil {
		return ErrUserNotFound
	}

	if data.Phone != nil {
		user.PhoneNumber = *data.Phone
	}
	if data.PhoneVerified != nil {
		user.PhoneVerified = *data.PhoneVerified
	}

	return s.UserRepo.Update(ctx, user)
}

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
