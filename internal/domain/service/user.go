package service

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

type UserService interface {
	Get(ctx context.Context, ID string) (*entity.User, error)
	//SetPassword(ctx context.Context, userID, passwOld, passNew string) error
}
