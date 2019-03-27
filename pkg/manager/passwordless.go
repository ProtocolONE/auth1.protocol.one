package manager

import (
	"auth-one-api/pkg/models"
)

type PasswordLessManager struct{}

func NewPasswordLessManager() *PasswordLessManager {
	m := &PasswordLessManager{}

	return m
}

func (m *PasswordLessManager) PasswordLessStart(form *models.PasswordLessStartForm) (ott *models.OneTimeToken, error *models.CommonError) {
	if form.ClientId == `incorrect` {
		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}
	if form.Connection == `incorrect` {
		return nil, &models.CommonError{Code: `connection`, Message: models.ErrorConnectionIncorrect}
	}

	return &models.OneTimeToken{
		Token: `onetimetoken`,
	}, nil
}

func (m *PasswordLessManager) PasswordLessVerify(form *models.PasswordLessVerifyForm) (token *models.AuthToken, error *models.CommonError) {
	if form.ClientId == `incorrect` {
		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}
	if form.Connection == `incorrect` {
		return nil, &models.CommonError{Code: `connection`, Message: models.ErrorConnectionIncorrect}
	}
	if form.Code == `incorrect` {
		return nil, &models.CommonError{Code: `verification_code`, Message: `Verification code is incorrect`}
	}
	if form.Token == `incorrect` {
		return nil, &models.CommonError{Code: `token`, Message: `Token is incorrect`}
	}

	return &models.AuthToken{
		RefreshToken: `refreshtoken`,
		AccessToken:  `accesstoken`,
		ExpiresIn:    1575983364,
	}, nil
}
