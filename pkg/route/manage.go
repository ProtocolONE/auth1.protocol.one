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

func InitManage(cfg Config) error {
	g := cfg.Echo.Group("/api", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(*mgo.Session)
			logger := c.Get("logger").(*zap.Logger)
			c.Set("manage_manager", manager.NewManageManager(db, logger, cfg.Hydra))

			return next(c)
		}
	})

	g.POST("/space", createSpace)
	g.PUT("/space/:id", updateSpace)
	g.GET("/space/:id", getSpace)
	g.POST("/app", createApplication)
	g.PUT("/app/:id", updateApplication)
	g.GET("/app/:id", getApplication)
	g.POST("/api/app/:id/password", setPasswordSettings)
	g.GET("/api/app/:id/password", getPasswordSettings)
	g.POST("/api/app/:id/identity", addIdentityProvider)
	g.PUT("/api/app/:app_id/identity/:id", updateIdentityProvider)
	g.GET("/api/app/:app_id/identity/:id", getIdentityProvider)
	g.GET("/api/app/:id/identity", getIdentityProviders)
	g.GET("/api/identity/templates", getIdentityProviderTemplates)
	g.POST("/mfa", addMFA)

	return nil
}

func createSpace(ctx echo.Context) error {
	form := &models.SpaceForm{}

	if err := ctx.Bind(form); err != nil {
		zap.L().Error(
			"CreateSpace bind form failed",
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
		zap.L().Error(
			"CreateSpace validate form failed",
			zap.Object("SpaceForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	m := ctx.Get("manage_manager").(*manager.ManageManager)

	s, err := m.CreateSpace(ctx, form)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to create the space")
	}

	return ctx.JSON(http.StatusOK, s)
}

func getSpace(ctx echo.Context) error {
	id := ctx.Param("id")

	m := ctx.Get("manage_manager").(*manager.ManageManager)

	space, err := m.GetSpace(ctx, id)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Space not exists")
	}

	return ctx.JSON(http.StatusOK, space)
}

func updateSpace(ctx echo.Context) error {
	id := ctx.Param("id")
	form := &models.SpaceForm{}

	if err := ctx.Bind(form); err != nil {
		zap.L().Error(
			"UpdateSpace bind form failed",
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
		zap.L().Error(
			"UpdateSpace validate form failed",
			zap.Object("SpaceForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	m := ctx.Get("manage_manager").(*manager.ManageManager)

	space, err := m.UpdateSpace(ctx, id, form)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to update the space")
	}

	return ctx.JSON(http.StatusOK, space)
}

func createApplication(ctx echo.Context) error {
	applicationForm := &models.ApplicationForm{}

	if err := ctx.Bind(applicationForm); err != nil {
		zap.L().Error(
			"CreateApplication bind form failed",
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(applicationForm); err != nil {
		zap.L().Error(
			"CreateApplication validate form failed",
			zap.Object("ApplicationForm", applicationForm),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	m := ctx.Get("manage_manager").(*manager.ManageManager)
	app, err := m.CreateApplication(ctx, applicationForm)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to create the application")
	}

	return ctx.JSON(http.StatusOK, app)
}

func getApplication(ctx echo.Context) error {
	id := ctx.Param("id")

	m := ctx.Get("manage_manager").(*manager.ManageManager)

	a, err := m.GetApplication(ctx, id)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Application not exists")
	}

	return ctx.JSON(http.StatusOK, a)
}

func updateApplication(ctx echo.Context) error {
	id := ctx.Param("id")
	applicationForm := &models.ApplicationForm{}

	if err := ctx.Bind(applicationForm); err != nil {
		zap.L().Error(
			"UpdateApplication bind form failed",
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(applicationForm); err != nil {
		zap.L().Error(
			"UpdateApplication validate form failed",
			zap.Object("ApplicationForm", applicationForm),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	m := ctx.Get("manage_manager").(*manager.ManageManager)
	app, err := m.UpdateApplication(ctx, id, applicationForm)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to update the application")
	}

	return ctx.JSON(http.StatusOK, app)
}

func addMFA(ctx echo.Context) error {
	mfaApplicationForm := &models.MfaApplicationForm{}

	if err := ctx.Bind(mfaApplicationForm); err != nil {
		zap.L().Error(
			"AddMFA bind form failed",
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(mfaApplicationForm); err != nil {
		zap.L().Error(
			"AddMFA validate form failed",
			zap.Object("MfaApplicationForm", mfaApplicationForm),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	m := ctx.Get("manage_manager").(*manager.ManageManager)
	app, err := m.AddMFA(ctx, mfaApplicationForm)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to create the application")
	}

	return ctx.JSON(http.StatusOK, app)
}

func setPasswordSettings(ctx echo.Context) error {
	form := &models.PasswordSettings{}

	if err := ctx.Bind(form); err != nil {
		zap.L().Error(
			"PasswordSettings bind form failed",
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		zap.L().Error(
			"PasswordSettings validate form failed",
			zap.Object("PasswordSettings", form),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	m := ctx.Get("manage_manager").(*manager.ManageManager)
	if err := m.SetPasswordSettings(ctx, form); err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to set password settings for the application")
	}

	return ctx.HTML(http.StatusOK, "")
}

func getPasswordSettings(ctx echo.Context) error {
	id := ctx.Param("id")

	m := ctx.Get("manage_manager").(*manager.ManageManager)
	ps, err := m.GetPasswordSettings(id)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Application not exists")
	}

	return ctx.JSON(http.StatusOK, ps)
}

func addIdentityProvider(ctx echo.Context) error {
	form := &models.AppIdentityProvider{}
	if err := ctx.Bind(form); err != nil {
		zap.L().Error(
			"AppIdentityProvider bind form failed",
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		zap.L().Error(
			"AppIdentityProvider validate form failed",
			zap.Object("AppIdentityProvider", form),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	m := ctx.Get("manage_manager").(*manager.ManageManager)
	if err := m.AddAppIdentityProvider(ctx, form); err != nil {
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
		return ctx.HTML(http.StatusBadRequest, "Identity provider not exists")
	}

	return ctx.JSON(http.StatusOK, ip)
}

func getIdentityProviders(ctx echo.Context) error {
	appID := ctx.Param("id")

	m := ctx.Get("manage_manager").(*manager.ManageManager)
	list, err := m.GetIdentityProviders(ctx, appID)
	if err != nil {
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
	if err := ctx.Bind(form); err != nil {
		zap.L().Error(
			"AppIdentityProvider bind form failed",
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		zap.L().Error(
			"AppIdentityProvider validate form failed",
			zap.Object("AppIdentityProvider", form),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	m := ctx.Get("manage_manager").(*manager.ManageManager)
	if err := m.UpdateAppIdentityProvider(ctx, id, form); err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to update the identity provider to the application")
	}

	return ctx.JSON(http.StatusOK, form)
}
