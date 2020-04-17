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

func (s Service) Get(ctx context.Context, ID string) (*entity.User, error) {
	return nil, nil
}
