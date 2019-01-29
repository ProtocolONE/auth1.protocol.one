package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"github.com/labstack/echo"
	"go.uber.org/zap"
	"gopkg.in/mgo.v2/bson"
	"net/http"
)

type LogoutManager struct {
	logger     *zap.Logger
	appService *models.ApplicationService
}

func NewLogoutManager(logger *zap.Logger, db *database.Handler) *LogoutManager {
	m := &LogoutManager{
		logger:     logger,
		appService: models.NewApplicationService(db),
	}

	return m
}

func (m *LogoutManager) Logout(r *echo.Response, form *models.LogoutForm) (error models.ErrorInterface) {
	if form.RedirectUri == `bad_redirect_uri` {
		return &models.CommonError{Message: models.ErrorRedirectUriIncorrect}
	}

	a, err := m.appService.Get(bson.ObjectIdHex(form.ClientId))
	if err != nil {
		m.logger.Error(
			"Unable to get application",
			zap.String("clientId", form.ClientId),
			zap.Error(err),
		)

		return &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	cs, err := m.appService.LoadSessionSettings()
	if err != nil {
		m.logger.Error(
			"Unable to load session settings an application",
			zap.String("appId", a.ID.String()),
			zap.Error(err),
		)

		return &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	c := models.NewCookie(a, &models.User{}).Clear(cs)
	if err != nil {
		m.logger.Error(
			"Unable to clear cookie an application",
			zap.String("appId", a.ID.String()),
			zap.Error(err),
		)

		return &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}

	http.SetCookie(r, c)
	return nil
}
