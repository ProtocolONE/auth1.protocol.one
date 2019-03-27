package route

import (
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/manager"
	"auth-one-api/pkg/models"
	"fmt"
	"github.com/globalsign/mgo"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"net/http"
)

func InitChangePassword(cfg Config) error {
	g := cfg.Echo.Group("/dbconnections", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(*mgo.Session)
			c.Set("password_manager", manager.NewChangePasswordManager(db, cfg.Redis))

			return next(c)
		}
	})

	g.POST("/change_password", changePasswordStart)
	g.POST("/change_password/verify", changePasswordVerify)

	return nil
}

func changePasswordStart(ctx echo.Context) error {
	form := new(models.ChangePasswordStartForm)

	if err := ctx.Bind(form); err != nil {
		zap.L().Error("ChangePasswordStart bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		zap.L().Error(
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

	m := ctx.Get("password_manager").(*manager.ChangePasswordManager)
	if err := m.ChangePasswordStart(form); err != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, err.GetCode(), err.GetMessage())
	}

	return ctx.NoContent(http.StatusOK)
}

func changePasswordVerify(ctx echo.Context) error {
	form := new(models.ChangePasswordVerifyForm)

	if err := ctx.Bind(form); err != nil {
		zap.L().Error("ChangePasswordVerify bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		zap.L().Error(
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

	m := ctx.Get("password_manager").(*manager.ChangePasswordManager)
	if err := m.ChangePasswordVerify(form); err != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, err.GetCode(), err.GetMessage())
	}

	return ctx.NoContent(http.StatusOK)
}
