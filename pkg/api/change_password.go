package api

import (
	"fmt"
	"net/http"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/labstack/echo/v4"
)

func InitChangePassword(cfg *Server) error {
	g := cfg.Echo.Group("/dbconnections", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(database.MgoSession)
			c.Set("password_manager", manager.NewChangePasswordManager(db, cfg.Registry, cfg.ServerConfig))

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
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
		}
		ctx.Error(err)
		return helper.JsonError(ctx, e)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
		}
		ctx.Error(err)
		return helper.JsonError(ctx, e)
	}

	if err := m.ChangePasswordStart(form); err != nil {
		ctx.Error(err.Err)
		return helper.JsonError(ctx, err)
	}

	return ctx.NoContent(http.StatusOK)
}

func changePasswordVerify(ctx echo.Context) error {
	form := new(models.ChangePasswordVerifyForm)
	m := ctx.Get("password_manager").(*manager.ChangePasswordManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
		}
		ctx.Error(err)
		return helper.JsonError(ctx, e)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
		}
		ctx.Error(err)
		return helper.JsonError(ctx, e)
	}

	if err := m.ChangePasswordVerify(form); err != nil {
		ctx.Error(err.Err)
		return helper.JsonError(ctx, err)
	}

	return ctx.NoContent(http.StatusOK)
}

func changePasswordForm(ctx echo.Context) error {
	form := new(models.ChangePasswordForm)
	m := ctx.Get("password_manager").(*manager.ChangePasswordManager)

	if err := ctx.Bind(form); err != nil {
		ctx.Error(err)
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	if err := ctx.Validate(form); err != nil {
		ctx.Error(err)
		return ctx.HTML(http.StatusBadRequest, models.ErrorRequiredField)
	}

	return ctx.Render(http.StatusOK, "change_password.html", map[string]interface{}{
		"AuthWebFormSdkUrl": m.ApiCfg.AuthWebFormSdkUrl,
		"ClientID":          form.ClientID,
	})
}
