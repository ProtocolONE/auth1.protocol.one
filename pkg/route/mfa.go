package route

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

func InitMFA(cfg Config) error {
	g := cfg.Echo.Group("/mfa", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(*mgo.Session)
			logger := c.Get("logger").(*zap.Logger)
			c.Set("mfa_manager", manager.NewMFAManager(db, logger, cfg.Redis, cfg.MfaService))

			return next(c)
		}
	})

	g.POST("/challenge", mfaChallenge)
	g.POST("/verify", mfaVerify)
	g.POST("/add", mfaAdd)

	return nil
}

func mfaChallenge(ctx echo.Context) error {
	form := new(models.MfaChallengeForm)
	m := ctx.Get("mfa_manager").(*manager.MFAManager)

	if err := ctx.Bind(form); err != nil {
		m.Logger.Error(
			"MFAChallenge bind form failed",
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
			"MFAChallenge validate form failed",
			zap.Object("MfaChallengeForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	e := m.MFAChallenge(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.HTML(http.StatusNoContent, ``)
}

func mfaVerify(ctx echo.Context) error {
	form := new(models.MfaVerifyForm)
	m := ctx.Get("mfa_manager").(*manager.MFAManager)

	if err := ctx.Bind(form); err != nil {
		m.Logger.Error(
			"MFAVerify bind form failed",
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
			"MFAVerify validate form failed",
			zap.Object("MfaVerifyForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	token, e := m.MFAVerify(ctx, form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}

func mfaAdd(ctx echo.Context) error {
	form := new(models.MfaAddForm)
	m := ctx.Get("mfa_manager").(*manager.MFAManager)

	if err := ctx.Bind(form); err != nil {
		m.Logger.Error(
			"MFAAdd bind form failed",
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
			"MFAAdd validate form failed",
			zap.Object("MfaAddForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	authenticator, e := m.MFAAdd(ctx, form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, authenticator)
}
