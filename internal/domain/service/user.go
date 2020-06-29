package service

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

type UserService interface {
	Update(ctx context.Context, data UpdateUserData) error

	GetByID(ctx context.Context, id entity.UserID) (*entity.User, error)
}

type UpdateUserData struct {
	ID            entity.UserID
	Phone         *string
	PhoneVerified *bool
}
