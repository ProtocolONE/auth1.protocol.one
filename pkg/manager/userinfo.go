package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/models"
	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
)

type UserInfoManager Config

func (m *UserInfoManager) UserInfo(ctx echo.Context) (t *models.UserProfile, error *models.AuthTokenError) {
	as := models.NewApplicationService(m.Database)
	c, err := helper.GetTokenFromAuthHeader(*as, ctx.Request().Header)
	if err != nil {
		return nil, &models.AuthTokenError{Code: `auth_token_invalid`, Message: err.Error()}
	}

	return &models.UserProfile{
		ID:            c.UserId,
		AppID:         c.AppId,
		Email:         c.Email,
		EmailVerified: c.EmailConfirmed,
	}, nil
}

func InitUserInfoManager(logger *logrus.Entry, db *database.Handler) UserInfoManager {
	m := UserInfoManager{
		Database: db,
		Logger:   logger,
	}

	return m
}
