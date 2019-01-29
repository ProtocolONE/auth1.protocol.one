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

type PasswordLess struct {
	Manager *manager.PasswordLessManager
	logger  *zap.Logger
}

func PasswordLessInit(cfg Config) error {
	route := &PasswordLess{
		Manager: manager.NewPasswordLessManager(cfg.Logger),
		logger:  cfg.Logger,
	}

	cfg.Echo.POST("/passwordless/start", route.PasswordLessStart)
	cfg.Echo.POST("/passwordless/verify", route.PasswordLessVerify)

	return nil
}

func (l *PasswordLess) PasswordLessStart(ctx echo.Context) error {
	form := new(models.PasswordLessStartForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("PasswordLessStart bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error("PasswordLessStart validate form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	token, e := l.Manager.PasswordLessStart(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}

func (l *PasswordLess) PasswordLessVerify(ctx echo.Context) error {
	form := new(models.PasswordLessVerifyForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("PasswordLessVerify bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error("PasswordLessVerify validate form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	token, e := l.Manager.PasswordLessVerify(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}
