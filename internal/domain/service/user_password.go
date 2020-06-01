package service

import (
	"context"
)

type UserPasswordService interface {
	SetPassword(ctx context.Context, data SetPasswordData) error
}

type SetPasswordData struct {
	AppID       string
	UserID      string
	PasswordOld string
	PasswordNew string
}
