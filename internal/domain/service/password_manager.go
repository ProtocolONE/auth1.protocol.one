package service

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

type PasswordManager interface {
	ChangePassword(ctx context.Context, userId entity.UserID, old, new string) error
}
