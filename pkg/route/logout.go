package route

import (
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/manager"
	"auth-one-api/pkg/models"
	"fmt"
	"github.com/labstack/echo"
	"net/http"
)

type Logout struct {
	Manager manager.LogoutManager
}

func LogoutInit(cfg Config) error {
	route := &Logout{
		Manager: manager.InitLogoutManager(cfg.Logger),
	}

	cfg.Echo.GET("/logout", route.Logout)

	return nil
}

func (l *Logout) Logout(ctx echo.Context) error {
	form := new(models.LogoutForm)

	if err := ctx.Bind(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			`Invalid request parameters`,
		)
	}

	if err := ctx.Validate(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			`This is required field`,
		)
	}

	err := l.Manager.Logout(form)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, err.GetMessage())
	}

	return ctx.Redirect(http.StatusOK, form.RedirectUri)
}
