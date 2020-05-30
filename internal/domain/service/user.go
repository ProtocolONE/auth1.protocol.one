package service

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

type UserService interface {
	GetByID(ctx context.Context, id entity.UserID) (*entity.User, error)
}
