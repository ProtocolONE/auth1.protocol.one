package manager

import (
	"auth-one-api/pkg/api/models"
	"github.com/sirupsen/logrus"
)

type ChangePasswordManager Config

func (m *ChangePasswordManager) ChangePasswordStart(form *models.ChangePasswordStartForm) (ott *models.OneTimeToken, error *models.CommonError) {
	if form.ClientId == `incorrect` {
		return nil, &models.CommonError{Code: `client_id`, Message: `Client ID is incorrect`}
	}
	if form.Connection == `incorrect` {
		return nil, &models.CommonError{Code: `connection`, Message: `Connection is incorrect`}
	}
	if form.Email == `login@incorrect.com` {
		return nil, &models.CommonError{Code: `email`, Message: `Login is incorrect`}
	}

	return &models.OneTimeToken{
		Token: `onetimetoken`,
	}, nil
}

func (m *ChangePasswordManager) ChangePasswordVerify(form *models.ChangePasswordVerifyForm) (token *models.JWTToken, error *models.CommonError) {
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
	if form.Password == `incorrect` {
		return nil, &models.CommonError{Code: `password`, Message: `Password is incorrect`}
	}

	return &models.JWTToken{
		RefreshToken: `refreshtoken`,
		AccessToken:  `accesstoken`,
		ExpiresIn:    1575983364,
	}, nil
}

func InitChangePasswordManager(logger *logrus.Entry) ChangePasswordManager {
	m := ChangePasswordManager{
		Logger: logger,
	}

	return m
}
