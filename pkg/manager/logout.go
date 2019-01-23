package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"fmt"
	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2/bson"
	"net/http"
)

type LogoutManager Config

func (m *LogoutManager) Logout(r *echo.Response, form *models.LogoutForm) (error models.ErrorInterface) {
	if form.RedirectUri == `bad_redirect_uri` {
		return &models.CommonError{Message: models.ErrorRedirectUriIncorrect}
	}

	as := models.NewApplicationService(m.Database)
	a, err := as.Get(bson.ObjectIdHex(form.ClientId))
	if err != nil {
		return &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	cs, err := as.LoadSessionSettings()
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to load session settings an application [%s] with error: %s", a.ID, err.Error()))
		return &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	c := models.NewCookie(a, &models.User{}).Clear(cs)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to clear cookie an application [%s] with error: %s", a.ID, err.Error()))
		return &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	http.SetCookie(r, c)

	return nil
}

func InitLogoutManager(logger *logrus.Entry, db *database.Handler) LogoutManager {
	m := LogoutManager{
		Database: db,
		Logger:   logger,
	}

	return m
}
