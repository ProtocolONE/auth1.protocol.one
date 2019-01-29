package route

import (
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/manager"
	"auth-one-api/pkg/models"
	"fmt"
	"github.com/labstack/echo"
	"go.uber.org/zap"
	"net/http"
)

type ChangePassword struct {
	Manager *manager.ChangePasswordManager
	logger  *zap.Logger
}

func ChangePasswordInit(cfg Config) error {
	route := &ChangePassword{
		Manager: manager.NewChangePasswordManager(cfg.Logger, cfg.Database, cfg.Redis),
		logger:  cfg.Logger,
	}

	cfg.Echo.POST("/dbconnections/change_password", route.ChangePasswordStart)
	cfg.Echo.POST("/dbconnections/change_password/verify", route.ChangePasswordVerify)

	return nil
}

func (l *ChangePassword) ChangePasswordStart(ctx echo.Context) error {
	form := new(models.ChangePasswordStartForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("ChangePasswordStart bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error("ChangePasswordStart validate form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	if err := l.Manager.ChangePasswordStart(form); err != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, err.GetCode(), err.GetMessage())
	}

	return ctx.NoContent(http.StatusOK)
}

func (l *ChangePassword) ChangePasswordVerify(ctx echo.Context) error {
	form := new(models.ChangePasswordVerifyForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("ChangePasswordVerify bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error("ChangePasswordVerify validate form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	if err := l.Manager.ChangePasswordVerify(form); err != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, err.GetCode(), err.GetMessage())
	}

	return ctx.NoContent(http.StatusOK)
}
