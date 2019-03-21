package route

import (
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/manager"
	"auth-one-api/pkg/models"
	"fmt"
	"github.com/labstack/echo"
	"go.uber.org/zap"
	"net/http"
)

type (
	Manage struct {
		Manager *manager.ManageManager
		Http    *echo.Echo
		logger  *zap.Logger
	}
)

func InitManage(cfg Config) error {
	route := &Manage{
		Manager: manager.NewManageManager(cfg.Logger, cfg.Database, cfg.Hydra),
		Http:    cfg.Echo,
		logger:  cfg.Logger,
	}

	cfg.Echo.POST("/api/space", route.CreateSpace)
	cfg.Echo.PUT("/api/space/:id", route.UpdateSpace)
	cfg.Echo.GET("/api/space/:id", route.GetSpace)
	cfg.Echo.POST("/api/app", route.CreateApplication)
	cfg.Echo.PUT("/api/app/:id", route.UpdateApplication)
	cfg.Echo.GET("/api/app/:id", route.GetApplication)
	cfg.Echo.POST("/api/app/:id/password", route.SetPasswordSettings)
	cfg.Echo.GET("/api/app/:id/password", route.GetPasswordSettings)
	cfg.Echo.POST("/api/app/:id/identity", route.AddIdentityProvider)
	cfg.Echo.PUT("/api/app/:app_id/identity/:id", route.UpdateIdentityProvider)
	cfg.Echo.GET("/api/app/:app_id/identity/:id", route.GetIdentityProvider)
	cfg.Echo.GET("/api/app/:id/identity", route.GetIdentityProviders)
	cfg.Echo.GET("/api/identity/templates", route.GetIdentityProviderTemplates)
	cfg.Echo.POST("/api/mfa", route.AddMFA)

	return nil
}

func (l *Manage) CreateSpace(ctx echo.Context) error {
	form := &models.SpaceForm{}

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("CreateSpace bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
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

	s, err := l.Manager.CreateSpace(form)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to create the space")
	}

	return ctx.JSON(http.StatusOK, s)
}

func (l *Manage) GetSpace(ctx echo.Context) error {
	id := ctx.Param("id")
	space, err := l.Manager.GetSpace(id)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Space not exists")
	}

	return ctx.JSON(http.StatusOK, space)
}

func (l *Manage) UpdateSpace(ctx echo.Context) error {
	id := ctx.Param("id")
	form := &models.SpaceForm{}

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("UpdateSpace bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
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

	space, err := l.Manager.UpdateSpace(id, form)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to update the space")
	}

	return ctx.JSON(http.StatusOK, space)
}

func (l *Manage) CreateApplication(ctx echo.Context) error {
	applicationForm := &models.ApplicationForm{}

	if err := ctx.Bind(applicationForm); err != nil {
		l.logger.Error("CreateApplication bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(applicationForm); err != nil {
		l.logger.Error(
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

	app, err := l.Manager.CreateApplication(ctx, applicationForm)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to create the application")
	}

	return ctx.JSON(http.StatusOK, app)
}

func (l *Manage) GetApplication(ctx echo.Context) error {
	id := ctx.Param("id")

	a, err := l.Manager.GetApplication(id)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Application not exists")
	}

	return ctx.JSON(http.StatusOK, a)
}

func (l *Manage) UpdateApplication(ctx echo.Context) error {
	id := ctx.Param("id")
	applicationForm := &models.ApplicationForm{}

	if err := ctx.Bind(applicationForm); err != nil {
		l.logger.Error("UpdateApplication bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(applicationForm); err != nil {
		l.logger.Error(
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

	app, err := l.Manager.UpdateApplication(ctx, id, applicationForm)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to update the application")
	}

	return ctx.JSON(http.StatusOK, app)
}

func (l *Manage) SetPasswordSettings(ctx echo.Context) error {
	form := &models.PasswordSettings{}

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("PasswordSettings bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
			"PasswordSettings validate form failed",
			zap.Object("PasswordSettings", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	if err := l.Manager.SetPasswordSettings(ctx, form); err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to set password settings for the application")
	}

	return ctx.HTML(http.StatusOK, "")
}

func (l *Manage) GetPasswordSettings(ctx echo.Context) error {
	id := ctx.Param("id")

	ps, err := l.Manager.GetPasswordSettings(id)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Application not exists")
	}

	return ctx.JSON(http.StatusOK, ps)
}

func (l *Manage) AddIdentityProvider(ctx echo.Context) error {
	form := &models.AppIdentityProvider{}
	if err := ctx.Bind(form); err != nil {
		l.logger.Error("AppIdentityProvider bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
			"AppIdentityProvider validate form failed",
			zap.Object("AppIdentityProvider", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	if err := l.Manager.AddAppIdentityProvider(ctx, form); err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to add the identity provider to the application")
	}

	return ctx.JSON(http.StatusOK, form)
}

func (l *Manage) GetIdentityProvider(ctx echo.Context) error {
	appID := ctx.Param("app_id")
	id := ctx.Param("id")

	ip, err := l.Manager.GetIdentityProvider(appID, id)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Identity provider not exists")
	}

	return ctx.JSON(http.StatusOK, ip)
}

func (l *Manage) GetIdentityProviders(ctx echo.Context) error {
	appID := ctx.Param("id")

	list, err := l.Manager.GetIdentityProviders(appID)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to give identity providers")
	}

	return ctx.JSON(http.StatusOK, list)
}

func (l *Manage) GetIdentityProviderTemplates(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, l.Manager.GetIdentityProviderTemplates())
}

func (l *Manage) UpdateIdentityProvider(ctx echo.Context) error {
	id := ctx.Param("id")
	form := &models.AppIdentityProvider{}
	if err := ctx.Bind(form); err != nil {
		l.logger.Error("AppIdentityProvider bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
			"AppIdentityProvider validate form failed",
			zap.Object("AppIdentityProvider", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	if err := l.Manager.UpdateAppIdentityProvider(ctx, id, form); err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to update the identity provider to the application")
	}

	return ctx.JSON(http.StatusOK, form)
}

func (l *Manage) AddMFA(ctx echo.Context) error {
	mfaApplicationForm := &models.MfaApplicationForm{}

	if err := ctx.Bind(mfaApplicationForm); err != nil {
		l.logger.Error("AddMFA bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(mfaApplicationForm); err != nil {
		l.logger.Error(
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

	app, err := l.Manager.AddMFA(mfaApplicationForm)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to create the application")
	}

	return ctx.JSON(http.StatusOK, app)
}
