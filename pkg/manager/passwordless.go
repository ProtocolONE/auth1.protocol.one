package manager

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/pkg/errors"
)

type PasswordLessManager struct {
}

func NewPasswordLessManager() *PasswordLessManager {
	m := &PasswordLessManager{}

	return m
}

func (m *PasswordLessManager) PasswordLessStart(form *models.PasswordLessStartForm) (ott *models.OneTimeToken, error *models.GeneralError) {
	if form.ClientId == `incorrect` {
		return nil, &models.GeneralError{Code: `client_id`, Message: models.ErrorClientIdIncorrect, Err: errors.New(models.ErrorClientIdIncorrect)}
	}
	if form.Connection == `incorrect` {
		return nil, &models.GeneralError{Code: `connection`, Message: models.ErrorConnectionIncorrect, Err: errors.New(models.ErrorConnectionIncorrect)}
	}

	return &models.OneTimeToken{
		Token: `onetimetoken`,
	}, nil
}

func (m *PasswordLessManager) PasswordLessVerify(form *models.PasswordLessVerifyForm) (token *models.AuthToken, error *models.GeneralError) {
	if form.ClientId == `incorrect` {
		return nil, &models.GeneralError{Code: `client_id`, Message: models.ErrorClientIdIncorrect, Err: errors.New(models.ErrorClientIdIncorrect)}
	}
	if form.Connection == `incorrect` {
		return nil, &models.GeneralError{Code: `connection`, Message: models.ErrorConnectionIncorrect, Err: errors.New(models.ErrorClientIdIncorrect)}
	}
	if form.Code == `incorrect` {
		return nil, &models.GeneralError{Code: `verification_code`, Message: `Verification code is incorrect`, Err: errors.New("Verification code is incorrect")}
	}
	if form.Token == `incorrect` {
		return nil, &models.GeneralError{Code: `token`, Message: `Token is incorrect`, Err: errors.New("Token is incorrect")}
	}

	return &models.AuthToken{
		RefreshToken: `refreshtoken`,
		AccessToken:  `accesstoken`,
		ExpiresIn:    1575983364,
	}, nil
}
