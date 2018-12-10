package route

import (
	"auth-one-api/pkg/api/manager"
	"auth-one-api/pkg/api/models"
	"auth-one-api/pkg/helper"
	"fmt"
	"github.com/labstack/echo"
	"net/http"
)

type Token struct {
	Manager manager.TokenManager
}

func TokenInit(cfg Config) error {
	route := &Token{
		Manager: manager.InitTokenManager(cfg.Logger),
	}

	cfg.Http.GET("/token/refresh", route.TokenRefresh)
	cfg.Http.GET("/token/ott", route.TokenOTT)

	return nil
}

func (l *Token) TokenRefresh(ctx echo.Context) error {
	token, e := l.Manager.Refresh()
	if e != nil {
		return helper.NewErrorResponse(ctx, BadRequiredHttpCode, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}

func (l *Token) TokenOTT(ctx echo.Context) error {
	form := new(models.TokenOttForm)

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

	token, e := l.Manager.OTT(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, BadRequiredHttpCode, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}
