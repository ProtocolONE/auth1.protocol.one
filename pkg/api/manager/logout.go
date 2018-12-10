package manager

import (
	"auth-one-api/pkg/api/models"
	"github.com/sirupsen/logrus"
)

type LogoutManager Config

func (m *LogoutManager) Logout(form *models.LogoutForm) (error models.ErrorInterface) {
	if form.ClientId == `unknown_client_id` {
		return &models.CommonError{Message: `Client ID is incorrect`}
	}
	if form.RedirectUri == `bad_redirect_uri` {
		return &models.CommonError{Message: `Redirect URI is incorrect`}
	}

	return nil
}

func InitLogoutManager(logger *logrus.Entry) LogoutManager {
	m := LogoutManager{
		Logger: logger,
	}

	return m
}
