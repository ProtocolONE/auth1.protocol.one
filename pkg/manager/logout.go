package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2/bson"
	"net/http"
)

type LogoutManager Config

func (m *LogoutManager) Logout(r *echo.Response, form *models.LogoutForm) (error models.ErrorInterface) {
	if form.RedirectUri == `bad_redirect_uri` {
		return &models.CommonError{Message: `Redirect URI is incorrect`}
	}

	a, err := models.NewApplicationService(m.Database).Get(bson.ObjectIdHex(form.ClientId))
	if err != nil {
		return &models.CommonError{Code: `client_id`, Message: `Client ID is incorrect`}
	}

	u := &models.User{}
	c := models.NewCookie(a, u).Clear(&models.CookieSettings{
		Name: "X-AUTH-ONE-TOKEN",
	})
	if err != nil {
		return &models.CommonError{Code: `common`, Message: `Unable to create cookie`}
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
