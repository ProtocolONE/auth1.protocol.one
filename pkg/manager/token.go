package manager

import (
	"auth-one-api/pkg/models"
	"go.uber.org/zap"
)

type TokenManager struct {
	logger *zap.Logger
}

func NewTokenManager(logger *zap.Logger) *TokenManager {
	m := &TokenManager{
		logger: logger,
	}

	return m
}

func (m *TokenManager) Refresh(form *models.RefreshTokenForm) (token *models.AuthToken, error *models.CommonError) {
	//UNDONE Right login
	return &models.AuthToken{
		RefreshToken: `refreshtoken`,
		AccessToken:  `accesstoken`,
		ExpiresIn:    1575983364,
	}, nil
}

func (m *TokenManager) OTT(form *models.OneTimeTokenForm) (token *models.AuthToken, error *models.CommonError) {
	if form.ClientId == `incorrect` {
		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
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
