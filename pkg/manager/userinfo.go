package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/models"
	"github.com/labstack/echo"
	"go.uber.org/zap"
)

type UserInfoManager struct {
	logger             *zap.Logger
	applicationService *models.ApplicationService
}

func NewUserInfoManager(logger *zap.Logger, db *database.Handler) *UserInfoManager {
	m := &UserInfoManager{
		logger:             logger,
		applicationService: models.NewApplicationService(db),
	}

	return m
}

func (m *UserInfoManager) UserInfo(ctx echo.Context) (t *models.UserProfile, error *models.AuthTokenError) {
	c, err := helper.GetTokenFromAuthHeader(m.applicationService, ctx.Request().Header)
	if err != nil {
		m.logger.Error(
			"Unable to get token from auth header",
			zap.Error(err),
		)

		return nil, &models.AuthTokenError{Code: `auth_token_invalid`, Message: err.Error()}
	}

	return &models.UserProfile{
		ID:            c.UserId,
		AppID:         c.AppId,
		Email:         c.Email,
		EmailVerified: c.EmailConfirmed,
	}, nil
}
