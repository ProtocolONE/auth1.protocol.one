package api

import (
	"fmt"
	"net/http"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/api/apierror"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/captcha"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra/sdk/go/hydra/client/admin"
)

func InitManage(cfg *Server) error {
	g := cfg.Echo.Group("/api", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(database.MgoSession)
			c.Set("manage_manager", manager.NewManageManager(db, cfg.Registry))
			c.Set("password_manager", manager.NewChangePasswordManager(db, cfg.Registry, cfg.ServerConfig, cfg.MailTemplates))
			c.Set("recaptcha", cfg.Recaptcha)
			c.Set("registry", cfg.Registry)

			return next(c)
		}
	})

	g.POST("/password/reset", passwordReset)
	g.POST("/password/reset/link", passwordResetCheck)
	g.POST("/password/reset/set", passwordResetSet)

	g.POST("/space", createSpace)
	g.PUT("/space/:id", updateSpace)
	g.GET("/space/:id", getSpace)
	g.POST("/app", createApplication)
	g.PUT("/app/:id", updateApplication)
	g.GET("/app/:id", getApplication)
	g.POST("/app/:id/password", setPasswordSettings)
	g.GET("/app/:id/password", getPasswordSettings)
	g.POST("/app/:id/identity", addIdentityProvider)
	g.PUT("/app/:app_id/identity/:id", updateIdentityProvider)
	g.GET("/app/:app_id/identity/:id", getIdentityProvider)
	g.GET("/app/:id/identity", getIdentityProviders)
	g.GET("/identity/templates", getIdentityProviderTemplates)
	g.POST("/app/:id/ott", setOneTimeTokenSettings)
	g.POST("/mfa", addMFA)

	return nil
}

// Password Reset

func passwordReset(ctx echo.Context) error {
	var r struct {
		CaptchaToken  string `query:"captchaToken" r:"captchaToken" validate:"required" json:"captchaToken"`
		CaptchaAction string `query:"captchaAction" r:"captchaAction" validate:"required" json:"captchaAction"`
		Challenge     string `query:"challenge" r:"challenge" validate:"required" json:"challenge"`
		Email         string `query:"email" r:"email" validate:"required" json:"email"`
	}

	if err := ctx.Bind(&r); err != nil {
		return apierror.InvalidRequest(err)
	}
	if err := ctx.Validate(r); err != nil {
		return apierror.InvalidParameters(err)
	}

	recaptcha := ctx.Get("recaptcha").(*captcha.Recaptcha)
	ok, err := recaptcha.Verify(ctx.Request().Context(), r.CaptchaToken, r.CaptchaAction, "")
	if err != nil {
		return apierror.Unknown(err)
	}
	if !ok {
		return apierror.CaptchaRequired
	}

	registry, ok := ctx.Get("registry").(service.InternalRegistry)
	if !ok {
		return apierror.Unknown(nil)
	}

	req, err := registry.HydraAdminApi().GetLoginRequest(&admin.GetLoginRequestParams{Challenge: r.Challenge, Context: ctx.Request().Context()})
	if err != nil {
		return apierror.InvalidChallenge
	}

	m, ok := ctx.Get("password_manager").(*manager.ChangePasswordManager)
	if !ok {
		return apierror.Unknown(nil)
	}

	form := &models.ChangePasswordStartForm{
		ClientID: req.Payload.Client.ClientID,
		Email:    r.Email,
	}
	if err := m.ChangePasswordStart(form); err != nil {
		ctx.Logger().Error(err.Error())
		ctx.Error(err.Err)
		return apierror.Unknown(err)
	}

	return ctx.JSON(http.StatusNoContent, map[string]string{
		"status": "ok",
	})
}

func passwordResetCheck(ctx echo.Context) error {
	var form struct {
		Token string `query:"token" form:"token" validate:"required" json:"token"`
	}

	if err := ctx.Bind(&form); err != nil {
		return apierror.InvalidRequest(err)
	}
	if err := ctx.Validate(form); err != nil {
		return apierror.InvalidParameters(err)
	}

	m := ctx.Get("password_manager").(*manager.ChangePasswordManager)

	email, err := m.ChangePasswordCheck(form.Token)
	if err != nil {
		return apierror.TokenOutdated
	}

	return ctx.JSON(http.StatusOK, map[string]string{
		"email": email,
	})
}

func passwordResetSet(ctx echo.Context) error {
	var form struct {
		Token    string `query:"token" form:"token" validate:"required" json:"token"`
		Password string `query:"password" form:"password" validate:"required" json:"password"`
	}

	if err := ctx.Bind(&form); err != nil {
		return apierror.InvalidRequest(err)
	}
	if err := ctx.Validate(form); err != nil {
		return apierror.InvalidParameters(err)
	}

	m := ctx.Get("password_manager").(*manager.ChangePasswordManager)
	f := &models.ChangePasswordVerifyForm{
		Token:          form.Token,
		Password:       form.Password,
		PasswordRepeat: form.Password,
	}
	if err := m.ChangePasswordVerify(f); err != nil {
		return apierror.Unknown(err)
	}

	// todo: logout & drop sessions

	// return URL to login
	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"url": "",
	})
}

// Manage

func createSpace(ctx echo.Context) error {
	form := &models.SpaceForm{}
	m := ctx.Get("manage_manager").(*manager.ManageManager)

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

	s, err := m.CreateSpace(ctx, form)
	if err != nil {
		ctx.Error(err.Err)
		return ctx.HTML(http.StatusBadRequest, "Unable to create the space")
	}

	return ctx.JSON(http.StatusOK, s)
}

func getSpace(ctx echo.Context) error {
	id := ctx.Param("id")
	m := ctx.Get("manage_manager").(*manager.ManageManager)

	space, err := m.GetSpace(ctx, id)
	if err != nil {
		ctx.Error(err.Err)
		return ctx.HTML(http.StatusBadRequest, "Space not exists")
	}

	return ctx.JSON(http.StatusOK, space)
}

func updateSpace(ctx echo.Context) error {
	id := ctx.Param("id")
	form := &models.SpaceForm{}
	m := ctx.Get("manage_manager").(*manager.ManageManager)

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

	space, err := m.UpdateSpace(ctx, id, form)
	if err != nil {
		ctx.Error(err.Err)
		return ctx.HTML(http.StatusBadRequest, "Unable to update the space")
	}

	return ctx.JSON(http.StatusOK, space)
}

func createApplication(ctx echo.Context) error {
	applicationForm := &models.ApplicationForm{}
	m := ctx.Get("manage_manager").(*manager.ManageManager)

	if err := ctx.Bind(applicationForm); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
		}
		ctx.Error(err)
		return helper.JsonError(ctx, e)
	}

	if err := ctx.Validate(applicationForm); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
		}
		ctx.Error(err)
		return helper.JsonError(ctx, e)
	}

	app, err := m.CreateApplication(ctx, applicationForm)
	if err != nil {
		ctx.Error(err.Err)
		return ctx.HTML(http.StatusBadRequest, "Unable to create the application")
	}

	return ctx.JSON(http.StatusOK, app)
}

func getApplication(ctx echo.Context) error {
	id := ctx.Param("id")

	m := ctx.Get("manage_manager").(*manager.ManageManager)

	a, err := m.GetApplication(ctx, id)
	if err != nil {
		ctx.Error(err.Err)
		return ctx.HTML(http.StatusBadRequest, "Application not exists")
	}

	return ctx.JSON(http.StatusOK, a)
}

func updateApplication(ctx echo.Context) error {
	id := ctx.Param("id")
	applicationForm := &models.ApplicationForm{}
	m := ctx.Get("manage_manager").(*manager.ManageManager)

	if err := ctx.Bind(applicationForm); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
		}
		ctx.Error(err)
		return helper.JsonError(ctx, e)
	}

	if err := ctx.Validate(applicationForm); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
		}
		ctx.Error(err)
		return helper.JsonError(ctx, e)
	}

	app, err := m.UpdateApplication(ctx, id, applicationForm)
	if err != nil {
		ctx.Error(err.Err)
		return ctx.HTML(http.StatusBadRequest, "Unable to update the application")
	}

	return ctx.JSON(http.StatusOK, app)
}

func addMFA(ctx echo.Context) error {
	mfaApplicationForm := &models.MfaApplicationForm{}
	m := ctx.Get("manage_manager").(*manager.ManageManager)

	if err := ctx.Bind(mfaApplicationForm); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
		}
		ctx.Error(err)
		return helper.JsonError(ctx, e)
	}

	if err := ctx.Validate(mfaApplicationForm); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
		}
		ctx.Error(err)
		return helper.JsonError(ctx, e)
	}

	app, err := m.AddMFA(ctx, mfaApplicationForm)
	if err != nil {
		ctx.Error(err.Err)
		return ctx.HTML(http.StatusBadRequest, "Unable to create the application")
	}

	return ctx.JSON(http.StatusOK, app)
}

func setPasswordSettings(ctx echo.Context) error {
	id := ctx.Param("id")
	form := &models.PasswordSettings{}
	m := ctx.Get("manage_manager").(*manager.ManageManager)

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

	if err := m.SetPasswordSettings(ctx, id, form); err != nil {
		ctx.Error(err.Err)
		return ctx.HTML(http.StatusBadRequest, "Unable to set password settings for the application")
	}

	return ctx.HTML(http.StatusOK, "")
}

func getPasswordSettings(ctx echo.Context) error {
	id := ctx.Param("id")

	m := ctx.Get("manage_manager").(*manager.ManageManager)
	ps, err := m.GetPasswordSettings(id)
	if err != nil {
		ctx.Error(err.Err)
		return ctx.HTML(http.StatusBadRequest, "Application not exists")
	}

	return ctx.JSON(http.StatusOK, ps)
}

func addIdentityProvider(ctx echo.Context) error {
	form := &models.AppIdentityProvider{}
	m := ctx.Get("manage_manager").(*manager.ManageManager)

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

	if err := m.AddAppIdentityProvider(ctx, form); err != nil {
		ctx.Error(err.Err)
		return ctx.HTML(http.StatusBadRequest, "Unable to add the identity provider to the application")
	}

	return ctx.JSON(http.StatusOK, form)
}

func getIdentityProvider(ctx echo.Context) error {
	appID := ctx.Param("app_id")
	id := ctx.Param("id")

	m := ctx.Get("manage_manager").(*manager.ManageManager)
	ip, err := m.GetIdentityProvider(ctx, appID, id)
	if err != nil {
		ctx.Error(err.Err)
		return ctx.HTML(http.StatusBadRequest, "Identity provider not exists")
	}

	return ctx.JSON(http.StatusOK, ip)
}

func getIdentityProviders(ctx echo.Context) error {
	appID := ctx.Param("id")

	m := ctx.Get("manage_manager").(*manager.ManageManager)
	list, err := m.GetIdentityProviders(ctx, appID)
	if err != nil {
		ctx.Error(err.Err)
		return ctx.HTML(http.StatusBadRequest, "Unable to give identity providers")
	}

	return ctx.JSON(http.StatusOK, list)
}

func getIdentityProviderTemplates(ctx echo.Context) error {
	m := ctx.Get("manage_manager").(*manager.ManageManager)
	return ctx.JSON(http.StatusOK, m.GetIdentityProviderTemplates())
}

func updateIdentityProvider(ctx echo.Context) error {
	id := ctx.Param("id")
	form := &models.AppIdentityProvider{}
	m := ctx.Get("manage_manager").(*manager.ManageManager)

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

	if err := m.UpdateAppIdentityProvider(ctx, id, form); err != nil {
		ctx.Error(err.Err)
		return ctx.HTML(http.StatusBadRequest, "Unable to update the identity provider to the application")
	}

	return ctx.JSON(http.StatusOK, form)
}

func setOneTimeTokenSettings(ctx echo.Context) error {
	id := ctx.Param("id")
	form := &models.OneTimeTokenSettings{}
	m := ctx.Get("manage_manager").(*manager.ManageManager)

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

	if err := m.SetOneTimeTokenSettings(ctx, id, form); err != nil {
		ctx.Error(err.Err)
		return ctx.HTML(http.StatusBadRequest, "Unable to set OneTimeToken settings for the application")
	}

	return ctx.HTML(http.StatusOK, "")
}
