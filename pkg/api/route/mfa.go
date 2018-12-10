package route

import (
	"auth-one-api/pkg/api/manager"
	"auth-one-api/pkg/api/models"
	"auth-one-api/pkg/helper"
	"fmt"
	"github.com/labstack/echo"
	"net/http"
)

type MFA struct {
	Manager manager.MFAManager
}

func MFAInit(cfg Config) error {
	route := &MFA{
		Manager: manager.InitMFAManager(cfg.Logger),
	}

	cfg.Http.POST("/mfa/challenge", route.MFAChallenge)
	cfg.Http.POST("/mfa/verify", route.MFAVerify)
	cfg.Http.POST("/mfa/add", route.MFAAdd)

	return nil
}

func (l *MFA) MFAChallenge(ctx echo.Context) error {
	form := new(models.MfaChallengeForm)

	if err := ctx.Bind(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			BadRequiredHttpCode,
			BadRequiredCodeCommon,
			`Invalid request parameters`,
		)
	}

	if err := ctx.Validate(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			BadRequiredHttpCode,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			`This is required field`,
		)
	}

	e := l.Manager.MFAChallenge(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, BadRequiredHttpCode, e.GetCode(), e.GetMessage())
	}

	return ctx.HTML(http.StatusNoContent, ``)
}

func (l *MFA) MFAVerify(ctx echo.Context) error {
	form := new(models.MfaVerifyForm)

	if err := ctx.Bind(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			BadRequiredHttpCode,
			BadRequiredCodeCommon,
			`Invalid request parameters`,
		)
	}

	if err := ctx.Validate(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			BadRequiredHttpCode,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			`This is required field`,
		)
	}

	token, e := l.Manager.MFAVerify(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, BadRequiredHttpCode, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}

func (l *MFA) MFAAdd(ctx echo.Context) error {
	form := new(models.MfaAddForm)

	if err := ctx.Bind(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			BadRequiredHttpCode,
			BadRequiredCodeCommon,
			`Invalid request parameters`,
		)
	}

	if err := ctx.Validate(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			BadRequiredHttpCode,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			`This is required field`,
		)
	}

	authenticator, e := l.Manager.MFAAdd(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, BadRequiredHttpCode, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, authenticator)
}
