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

func ManageInit(cfg Config) error {
	route := &Manage{
		Manager: manager.NewManageManager(cfg.Logger, cfg.Database),
		Http:    cfg.Echo,
		logger:  cfg.Logger,
	}

	cfg.Echo.POST("/api/space", route.CreateSpace)
	cfg.Echo.PUT("/api/space/:id", route.UpdateSpace)
	cfg.Echo.GET("/api/space/:id", route.GetSpace)
	cfg.Echo.POST("/api/app", route.CreateApplication)
	cfg.Echo.PUT("/api/app/:id", route.UpdateApplication)
	cfg.Echo.GET("/api/app/:id", route.GetApplication)
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

	app, err := l.Manager.CreateApplication(applicationForm)
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

	app, err := l.Manager.UpdateApplication(id, applicationForm)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to update the application")
	}

	return ctx.JSON(http.StatusOK, app)
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
