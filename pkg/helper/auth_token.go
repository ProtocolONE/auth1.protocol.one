package helper

import (
	"auth-one-api/pkg/models"
	"errors"
	"github.com/labstack/echo"
	"time"
)

func CreateAuthToken(ctx echo.Context, as *models.ApplicationService, u *models.User) (t *models.AuthToken, err error) {
	ats, err := as.LoadAuthTokenSettings()
	if err != nil {
		return nil, errors.New("unable to create token")
	}

	jts := models.NewJwtTokenService(ats)
	at, err := jts.Create(u)
	if err != nil {
		return nil, errors.New("unable to create token")
	}

	rts := models.NewRefreshTokenService(ats)
	rt := rts.Create(ctx.Request().UserAgent(), ctx.RealIP())

	return &models.AuthToken{
		RefreshToken: rt.Value,
		AccessToken:  at,
		ExpiresIn:    time.Now().Unix() + int64(ats.JwtTTL),
	}, nil
}
