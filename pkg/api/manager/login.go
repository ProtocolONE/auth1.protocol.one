package manager

import (
	"auth-one-api/pkg/api/models"
	"github.com/sirupsen/logrus"
)

type LoginManager Config

func (m *LoginManager) Authorize(form *models.AuthorizeForm) (ott *models.OneTimeToken, error models.ErrorInterface) {
	if form.ClientId == `incorrect` {
		return nil, &models.CommonError{Message: `Connection is incorrect`}
	}
	if form.Connection == `incorrect` {
		return nil, &models.CommonError{Message: `Connection is incorrect`}
	}
	if form.RedirectUri == `incorrect` {
		return nil, &models.CommonError{Message: `Redirect URI is incorrect`}
	}

	return &models.OneTimeToken{
		Token: `onetimetoken`,
	}, nil
}

func (m *LoginManager) AuthorizeResult(form *models.AuthorizeResultForm) (error models.ErrorInterface) {
	if form.ClientId == `incorrect` {
		return &models.CommonError{Code: `connection`, Message: `Connection is incorrect`}
	}
	if form.Connection == `incorrect` {
		return &models.CommonError{Code: `connection`, Message: `Connection is incorrect`}
	}
	if form.OTT == `incorrect` {
		return &models.CommonError{Code: `auth_one_ott`, Message: `OTT is incorrect`}
	}

	return nil
}

func (m *LoginManager) Login(form *models.LoginForm) (token *models.JWTToken, error models.ErrorInterface) {
	if form.Email == `captcha@required.com` {
		return nil, &models.CaptchaRequiredError{Message: `Captcha required`}
	}
	if form.Email == `mfa@required.com` {
		return nil, &models.MFARequiredError{Message: `MFA required`}
	}
	if form.Email == `temporary@locked.com` {
		return nil, &models.TemporaryLockedError{Message: `Temporary locked`}
	}
	if form.Email == `login@incorrect.com` {
		return nil, &models.CommonError{Code: `email`, Message: `Login is incorrect`}
	}
	if form.Password == `incorrect` {
		return nil, &models.CommonError{Code: `password`, Message: `Password is incorrect`}
	}
	if form.Captcha == `incorrect` {
		return nil, &models.CommonError{Code: `captcha`, Message: `Captcha is incorrect`}
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

func InitLoginManager(logger *logrus.Entry) LoginManager {
	m := LoginManager{
		Logger: logger,
	}

	return m
}
