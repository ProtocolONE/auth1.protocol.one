package manager

import (
	"auth-one-api/pkg/models"
	"github.com/sirupsen/logrus"
)

type SignUpManager Config

func (m *SignUpManager) SignUp(form *models.SignUpForm) (token *models.JWTToken, error *models.CommonError) {
	if form.Email == `login@incorrect.com` {
		return nil, &models.CommonError{Code: `email`, Message: `Login is incorrect`}
	}
	if form.Password == `incorrect` {
		return nil, &models.CommonError{Code: `password`, Message: `Password is incorrect`}
	}
	if form.Connection == `incorrect` {
		return nil, &models.CommonError{Code: `connection`, Message: `Connection is incorrect`}
	}
	if form.ClientId == `incorrect` {
		return nil, &models.CommonError{Code: `client_id`, Message: `Client ID is incorrect`}
	}

	return &models.JWTToken{
		RefreshToken: `refreshtoken`,
		AccessToken:  `accesstoken`,
		ExpiresIn:    1575983364,
	}, nil
}

func InitSignUpManager(logger *logrus.Entry) SignUpManager {
	m := SignUpManager{
		Logger: logger,
	}

	return m
}
