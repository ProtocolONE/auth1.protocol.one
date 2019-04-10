package api

import (
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"net/http"
)

func InitMFA(cfg *Server) error {
	g := cfg.Echo.Group("/mfa", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(*mgo.Session)
			logger := c.Get("logger").(*zap.Logger)
			c.Set("mfa_manager", manager.NewMFAManager(db, logger, cfg.RedisHandler, cfg.Registry))

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
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "MFAChallenge bind form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return ctx.HTML(http.StatusBadRequest, e.Message)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
			Error:   errors.Wrap(err, "MFAChallenge validate form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return ctx.HTML(http.StatusBadRequest, e.Message)
	}

	err := m.MFAChallenge(form)
	if err != nil {
		helper.SaveErrorLog(ctx, m.Logger, err)
		return ctx.HTML(http.StatusBadRequest, err.Message)
	}

	return ctx.HTML(http.StatusNoContent, "")
}

func mfaVerify(ctx echo.Context) error {
	form := new(models.MfaVerifyForm)
	m := ctx.Get("mfa_manager").(*manager.MFAManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "MFAVerify bind form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
			Error:   errors.Wrap(err, "MFAVerify validate form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	token, err := m.MFAVerify(ctx, form)
	if err != nil {
		helper.SaveErrorLog(ctx, m.Logger, err)
		return ctx.JSON(http.StatusBadRequest, err)
	}

	return ctx.JSON(http.StatusOK, token)
}

func mfaAdd(ctx echo.Context) error {
	form := new(models.MfaAddForm)
	m := ctx.Get("mfa_manager").(*manager.MFAManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "MFAAdd bind form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
			Error:   errors.Wrap(err, "MFAAdd validate form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	authenticator, err := m.MFAAdd(ctx, form)
	if err != nil {
		helper.SaveErrorLog(ctx, m.Logger, err)
		return ctx.JSON(http.StatusBadRequest, err)
	}

	return ctx.JSON(http.StatusOK, authenticator)
}