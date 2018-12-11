package manager

import (
	"auth-one-api/pkg/models"
	"github.com/sirupsen/logrus"
)

type UserInfoManager Config

func (m *UserInfoManager) UserInfo(tokenSource string) (token *models.JWTToken, error *models.AuthTokenError) {
	if `incorrect` == tokenSource {
		return nil, &models.AuthTokenError{Code: `auth_token_invalid`, Message: `Invalid authenticate token`}
	}

	return &models.JWTToken{
		RefreshToken: `refreshtoken`,
		AccessToken:  `accesstoken`,
		ExpiresIn:    1575983364,
	}, nil
}

func InitUserInfoManager(logger *logrus.Entry) UserInfoManager {
	m := UserInfoManager{
		Logger: logger,
	}

	return m
}
