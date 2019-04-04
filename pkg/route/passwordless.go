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
	g := cfg.Echo.Group("/passwordless", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			logger := c.Get("logger").(*zap.Logger)
			c.Set("passwordless_manager", manager.NewPasswordLessManager(logger))

			return next(c)
		}
	})

	g.POST("/start", passwordLessStart)
	g.POST("/verify", passwordLessVerify)

	return nil
}

func passwordLessStart(ctx echo.Context) error {
	form := new(models.PasswordLessStartForm)
	m := ctx.Get("passwordless_manager").(*manager.PasswordLessManager)

	if err := ctx.Bind(form); err != nil {
		m.Logger.Error(
			"PasswordLessStart bind form failed",
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		m.Logger.Error(
			"PasswordLessStart validate form failed",
			zap.Object("PasswordLessStartForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	token, e := m.PasswordLessStart(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}

func passwordLessVerify(ctx echo.Context) error {
	form := new(models.PasswordLessVerifyForm)
	m := ctx.Get("passwordless_manager").(*manager.PasswordLessManager)

	if err := ctx.Bind(form); err != nil {
		m.Logger.Error(
			"PasswordLessVerify bind form failed",
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		m.Logger.Error(
			"PasswordLessVerify validate form failed",
			zap.Object("PasswordLessVerifyForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	token, e := m.PasswordLessVerify(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}
