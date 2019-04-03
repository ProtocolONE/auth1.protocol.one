package route

import (
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"net/http"
)

func InitPasswordLess(cfg Config) error {
	cfg.Echo.POST("/passwordless/start", passwordLessStart)
	cfg.Echo.POST("/passwordless/verify", passwordLessVerify)

	return nil
}

func passwordLessStart(ctx echo.Context) error {
	form := new(models.PasswordLessStartForm)

	if err := ctx.Bind(form); err != nil {
		zap.L().Error(
			"PasswordLessStart bind form failed",
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		zap.L().Error(
			"PasswordLessStart validate form failed",
			zap.Object("PasswordLessStartForm", form),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}
	m := manager.NewPasswordLessManager()

	token, e := m.PasswordLessStart(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}

func passwordLessVerify(ctx echo.Context) error {
	form := new(models.PasswordLessVerifyForm)

	if err := ctx.Bind(form); err != nil {
		zap.L().Error(
			"PasswordLessVerify bind form failed",
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		zap.L().Error(
			"PasswordLessVerify validate form failed",
			zap.Object("PasswordLessVerifyForm", form),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	m := manager.NewPasswordLessManager()

	token, e := m.PasswordLessVerify(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}
