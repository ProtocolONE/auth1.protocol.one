package route

import (
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/manager"
	"auth-one-api/pkg/models"
	"fmt"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"net/http"
)

type MFA struct {
	Manager *manager.MFAManager
	logger  *zap.Logger
}

func InitMFA(cfg Config) error {
	route := &MFA{
		Manager: manager.NewMFAManager(cfg.Logger, cfg.Database, cfg.Redis, cfg.MfaService),
		logger:  cfg.Logger,
	}

	cfg.Echo.POST("/mfa/challenge", route.MFAChallenge)
	cfg.Echo.POST("/mfa/verify", route.MFAVerify)
	cfg.Echo.POST("/mfa/add", route.MFAAdd)

	return nil
}

func (l *MFA) MFAChallenge(ctx echo.Context) error {
	form := new(models.MfaChallengeForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("MFAChallenge bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
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

	e := l.Manager.MFAChallenge(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.HTML(http.StatusNoContent, ``)
}

func (l *MFA) MFAVerify(ctx echo.Context) error {
	form := new(models.MfaVerifyForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("MFAVerify bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
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

	token, e := l.Manager.MFAVerify(ctx, form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}

func (l *MFA) MFAAdd(ctx echo.Context) error {
	form := new(models.MfaAddForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("MFAAdd bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
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

	authenticator, e := l.Manager.MFAAdd(ctx, form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, authenticator)
}
