package captcha

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/labstack/echo/v4"
)

const captchaKey = "captcha"

// IsCompleted checks if session has flag that captcha was verified
func IsCompleted(ctx echo.Context, s service.SessionService) (bool, error) {
	v, err := s.Get(ctx, captchaKey)
	if err != nil {
		return false, err
	}
	if v != nil {
		if done, ok := v.(bool); ok {
			return done, nil
		}
	}
	return false, nil
}

// StoreCompletedStatus attachs captcha verification status to client session
func StoreCompletedStatus(ctx echo.Context, s service.SessionService, value bool) error {
	return s.Set(ctx, captchaKey, value)
}
