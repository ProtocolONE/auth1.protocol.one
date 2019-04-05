package api

import (
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"net/http"
)

func InitChangePassword(cfg *Server) error {
	g := cfg.Echo.Group("/dbconnections", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(*mgo.Session)
			logger := c.Get("logger").(*zap.Logger)
			c.Set("password_manager", manager.NewChangePasswordManager(db, logger, cfg.RedisHandler, cfg.Registry))

			return next(c)
		}
	})

	g.POST("/change_password", changePasswordStart)
	g.POST("/change_password/verify", changePasswordVerify)
	g.GET("/change_password/form", changePasswordForm)

	return nil
}

func changePasswordStart(ctx echo.Context) error {
	form := new(models.ChangePasswordStartForm)
	m := ctx.Get("password_manager").(*manager.ChangePasswordManager)

	if err := ctx.Bind(form); err != nil {
		m.Logger.Error(
			"ChangePasswordStart bind form failed",
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
			"ChangePasswordStart validate form failed",
			zap.Object("ChangePasswordStartForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	if err := m.ChangePasswordStart(form); err != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, err.GetCode(), err.GetMessage())
	}

	return ctx.NoContent(http.StatusOK)
}

func changePasswordVerify(ctx echo.Context) error {
	form := new(models.ChangePasswordVerifyForm)
	m := ctx.Get("password_manager").(*manager.ChangePasswordManager)

	if err := ctx.Bind(form); err != nil {
		m.Logger.Error(
			"ChangePasswordVerify bind form failed",
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
			"ChangePasswordVerify validate form failed",
			zap.Object("ChangePasswordVerifyForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	if err := m.ChangePasswordVerify(form); err != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, err.GetCode(), err.GetMessage())
	}

	return ctx.NoContent(http.StatusOK)
}

func changePasswordForm(ctx echo.Context) error {
	form := new(models.ChangePasswordForm)
	m := ctx.Get("password_manager").(*manager.ChangePasswordManager)

	if err := ctx.Bind(form); err != nil {
		m.Logger.Error(
			"ChangePasswordForm bind form failed",
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
			"ChangePasswordForm validate form failed",
			zap.Object("ChangePasswordForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	return ctx.Render(http.StatusOK, "change_password.html", map[string]interface{}{
		"ClientID": form.ClientID,
	})
}
