package manager

import (
	"auth-one-api/pkg/models"
	"github.com/sirupsen/logrus"
)

type PasswordLessManager Config

func (m *PasswordLessManager) PasswordLessStart(form *models.PasswordLessStartForm) (ott *models.OneTimeToken, error *models.CommonError) {
	if form.ClientId == `incorrect` {
		return nil, &models.CommonError{Code: `client_id`, Message: `Client ID is incorrect`}
	}
	if form.Connection == `incorrect` {
		return nil, &models.CommonError{Code: `connection`, Message: `Connection is incorrect`}
	}

	return &models.OneTimeToken{
		Token: `onetimetoken`,
	}, nil
}

func (m *PasswordLessManager) PasswordLessVerify(form *models.PasswordLessVerifyForm) (token *models.JWTToken, error *models.CommonError) {
	if form.ClientId == `incorrect` {
		return nil, &models.CommonError{Code: `client_id`, Message: `Client ID is incorrect`}
	}
	if form.Connection == `incorrect` {
		return nil, &models.CommonError{Code: `connection`, Message: `Connection is incorrect`}
	}
	if form.Code == `incorrect` {
		return nil, &models.CommonError{Code: `verification_code`, Message: `Verification code is incorrect`}
	}
	if form.Token == `incorrect` {
		return nil, &models.CommonError{Code: `token`, Message: `Token is incorrect`}
	}

	return &models.JWTToken{
		RefreshToken: `refreshtoken`,
		AccessToken:  `accesstoken`,
		ExpiresIn:    1575983364,
	}, nil
}

func InitPasswordLessManager(logger *logrus.Entry) PasswordLessManager {
	m := PasswordLessManager{
		Logger: logger,
	}

	return m
}
