package route

import (
	"auth-one-api/pkg/api/manager"
	"auth-one-api/pkg/api/models"
	"auth-one-api/pkg/helper"
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

	cfg.Http.GET("/logout", route.Logout)

	return nil
}

func (l *Logout) Logout(ctx echo.Context) error {
	form := new(models.LogoutForm)

	if err := ctx.Bind(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			BadRequiredHttpCode,
			BadRequiredCodeCommon,
			`Invalid request parameters`,
		)
	}

	if err := ctx.Validate(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			BadRequiredHttpCode,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			`This is required field`,
		)
	}

	err := l.Manager.Logout(form)
	if err != nil {
		return ctx.HTML(BadRequiredHttpCode, err.GetMessage())
	}

	return ctx.Redirect(http.StatusOK, form.RedirectUri)
}
