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

func InitMFA(cfg *Server) error {
	g := cfg.Echo.Group("/mfa", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(database.MgoSession)
			c.Set("mfa_manager", manager.NewMFAManager(db, cfg.Registry))

			return next(c)
		}
	})

	g.POST("/challenge", mfaChallenge)
	g.POST("/verify", mfaVerify)
	g.POST("/add", mfaAdd)
	g.POST("/list", mfaList)
	g.POST("/remove", mfaRemove)

	return nil
}

func mfaList(ctx echo.Context) error {
	form := new(models.MfaListForm)
	m := ctx.Get("mfa_manager").(*manager.MFAManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
		}
		ctx.Error(err)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
		}
		ctx.Error(err)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	list, err := m.MFAList(ctx, form)
	if err != nil {
		ctx.Error(err.Err)
		return ctx.JSON(http.StatusBadRequest, err)
	}

	return ctx.JSON(http.StatusOK, list)
}

func mfaRemove(ctx echo.Context) error {
	form := new(models.MfaRemoveForm)
	m := ctx.Get("mfa_manager").(*manager.MFAManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
		}
		ctx.Error(err)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
		}
		ctx.Error(err)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	err := m.MFARemove(ctx, form)
	if err != nil {
		ctx.Error(err.Err)
		return ctx.JSON(http.StatusBadRequest, err)
	}

	return ctx.NoContent(http.StatusOK)
}

func mfaChallenge(ctx echo.Context) error {
	form := new(models.MfaChallengeForm)
	m := ctx.Get("mfa_manager").(*manager.MFAManager)

	if err := ctx.Bind(form); err != nil {
		ctx.Error(err)
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	if err := ctx.Validate(form); err != nil {
		ctx.Error(err)
		return ctx.HTML(http.StatusBadRequest, models.ErrorRequiredField)
	}

	err := m.MFAChallenge(form)
	if err != nil {
		ctx.Error(err.Err)
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
		}
		ctx.Error(err)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
		}
		ctx.Error(err)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	err := m.MFAVerify(ctx, form)
	if err != nil {
		ctx.Error(err.Err)
		return ctx.JSON(http.StatusBadRequest, err)
	}

	return ctx.JSON(http.StatusOK, "")
}

func mfaAdd(ctx echo.Context) error {
	form := new(models.MfaAddForm)
	m := ctx.Get("mfa_manager").(*manager.MFAManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
		}
		ctx.Error(err)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
		}
		ctx.Error(err)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	authenticator, err := m.MFAAdd(ctx, form)
	if err != nil {
		ctx.Error(err.Err)
		return ctx.JSON(http.StatusBadRequest, err)
	}

	return ctx.JSON(http.StatusOK, authenticator)
}
