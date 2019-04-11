package api

import (
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"net/http"
)

func InitChangePassword(cfg *Server) error {
	g := cfg.Echo.Group("/dbconnections", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(*mgo.Session)
			c.Set("password_manager", manager.NewChangePasswordManager(db, cfg.RedisHandler, cfg.Registry))

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
			Err:     errors.Wrap(err, "ChangePasswordStart bind form failed"),
		}
		return helper.JsonError(ctx, e)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
			Err:     errors.Wrap(err, "ChangePasswordStart validate form failed"),
		}
		return helper.JsonError(ctx, e)
	}

	if err := m.ChangePasswordStart(form); err != nil {
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
			Err:     errors.Wrap(err, "ChangePasswordVerify bind form failed"),
		}
		return helper.JsonError(ctx, e)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
			Err:     errors.Wrap(err, "ChangePasswordVerify validate form failed"),
		}
		return helper.JsonError(ctx, e)
	}

	if err := m.ChangePasswordVerify(form); err != nil {
		return helper.JsonError(ctx, err)
	}

	return ctx.NoContent(http.StatusOK)
}

func changePasswordForm(ctx echo.Context) error {
	form := new(models.ChangePasswordForm)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Err:     errors.Wrap(err, "ChangePasswordForm bind form failed"),
		}
		return ctx.HTML(http.StatusBadRequest, e.Message)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
			Err:     errors.Wrap(err, "ChangePasswordForm validate form failed"),
		}
		return ctx.HTML(http.StatusBadRequest, e.Message)
	}

	return ctx.Render(http.StatusOK, "change_password.html", map[string]interface{}{
		"ClientID": form.ClientID,
	})
}
