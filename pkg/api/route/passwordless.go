package route

import (
	"auth-one-api/pkg/api/manager"
	"auth-one-api/pkg/api/models"
	"auth-one-api/pkg/helper"
	"fmt"
	"github.com/labstack/echo"
	"net/http"
)

type PasswordLess struct {
	Manager manager.PasswordLessManager
}

func PasswordLessInit(cfg Config) error {
	route := &PasswordLess{
		Manager: manager.InitPasswordLessManager(cfg.Logger),
	}

	cfg.Http.POST("/passwordless/start", route.PasswordLessStart)
	cfg.Http.POST("/passwordless/verify", route.PasswordLessVerify)

	return nil
}

func (l *PasswordLess) PasswordLessStart(ctx echo.Context) error {
	form := new(models.PasswordLessStartForm)

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

	token, e := l.Manager.PasswordLessStart(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, BadRequiredHttpCode, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}

func (l *PasswordLess) PasswordLessVerify(ctx echo.Context) error {
	form := new(models.PasswordLessVerifyForm)

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

	token, e := l.Manager.PasswordLessVerify(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, BadRequiredHttpCode, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}
