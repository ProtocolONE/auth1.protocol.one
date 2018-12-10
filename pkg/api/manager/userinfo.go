package manager

import (
	"auth-one-api/pkg/api/models"
	"github.com/sirupsen/logrus"
)

type UserInfoManager Config

func (m *UserInfoManager) UserInfo() (token *models.JWTToken, error *models.CommonError) {
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
