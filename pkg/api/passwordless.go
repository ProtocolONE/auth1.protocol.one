package api

import (
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"net/http"
)

func InitPasswordLess(cfg *Server) error {
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
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "PasswordLessStart bind form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
			Error:   errors.Wrap(err, "PasswordLessStart validate form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	token, err := m.PasswordLessStart(form)
	if err != nil {
		helper.SaveErrorLog(ctx, m.Logger, err)
		return ctx.JSON(http.StatusBadRequest, err)
	}

	return ctx.JSON(http.StatusOK, token)
}

func passwordLessVerify(ctx echo.Context) error {
	form := new(models.PasswordLessVerifyForm)
	m := ctx.Get("passwordless_manager").(*manager.PasswordLessManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "PasswordLessVerify bind form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
			Error:   errors.Wrap(err, "PasswordLessVerify validate form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	token, err := m.PasswordLessVerify(form)
	if err != nil {
		helper.SaveErrorLog(ctx, m.Logger, err)
		return ctx.JSON(http.StatusBadRequest, err)
	}

	return ctx.JSON(http.StatusOK, token)
}
