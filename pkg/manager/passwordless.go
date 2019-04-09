package manager

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"go.uber.org/zap"
)

type PasswordLessManager struct {
	Logger *zap.Logger
}

func NewPasswordLessManager(l *zap.Logger) *PasswordLessManager {
	m := &PasswordLessManager{
		Logger: l,
	}

	return m
}

func (m *PasswordLessManager) PasswordLessStart(form *models.PasswordLessStartForm) (ott *models.OneTimeToken, error *models.GeneralError) {
	if form.ClientId == `incorrect` {
		return nil, &models.GeneralError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}
	if form.Connection == `incorrect` {
		return nil, &models.GeneralError{Code: `connection`, Message: models.ErrorConnectionIncorrect}
	}

	return &models.OneTimeToken{
		Token: `onetimetoken`,
	}, nil
}

func (m *PasswordLessManager) PasswordLessVerify(form *models.PasswordLessVerifyForm) (token *models.AuthToken, error *models.GeneralError) {
	if form.ClientId == `incorrect` {
		return nil, &models.GeneralError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}
	if form.Connection == `incorrect` {
		return nil, &models.GeneralError{Code: `connection`, Message: models.ErrorConnectionIncorrect}
	}
	if form.Code == `incorrect` {
		return nil, &models.GeneralError{Code: `verification_code`, Message: `Verification code is incorrect`}
	}
	if form.Token == `incorrect` {
		return nil, &models.GeneralError{Code: `token`, Message: `Token is incorrect`}
	}

	return &models.AuthToken{
		RefreshToken: `refreshtoken`,
		AccessToken:  `accesstoken`,
		ExpiresIn:    1575983364,
	}, nil
}
