package route

import (
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/manager"
	"auth-one-api/pkg/models"
	"fmt"
	"github.com/labstack/echo"
	"net/http"
)

type ChangePassword struct {
	Manager manager.ChangePasswordManager
}

func ChangePasswordInit(cfg Config) error {
	route := &ChangePassword{
		Manager: manager.InitChangePasswordManager(cfg.Logger, cfg.Database, cfg.Redis),
	}

	cfg.Echo.POST("/dbconnections/change_password", route.ChangePasswordStart)
	cfg.Echo.POST("/dbconnections/change_password/verify", route.ChangePasswordVerify)

	return nil
}

func (l *ChangePassword) ChangePasswordStart(ctx echo.Context) error {
	form := new(models.ChangePasswordStartForm)

	if err := ctx.Bind(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	if e := l.Manager.ChangePasswordStart(form); e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.NoContent(http.StatusOK)
}

func (l *ChangePassword) ChangePasswordVerify(ctx echo.Context) error {
	form := new(models.ChangePasswordVerifyForm)

	if err := ctx.Bind(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	if e := l.Manager.ChangePasswordVerify(form); e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.NoContent(http.StatusOK)
}
