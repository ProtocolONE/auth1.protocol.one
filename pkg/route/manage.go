package route

import (
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/manager"
	"auth-one-api/pkg/models"
	"fmt"
	"github.com/labstack/echo"
	"net/http"
)

type (
	Manage struct {
		Manager manager.ManageManager
		Http    *echo.Echo
	}
)

func ManageInit(cfg Config) error {
	route := &Manage{
		Manager: manager.InitManageManager(cfg.Logger, cfg.Database),
		Http:    cfg.Echo,
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
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
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
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
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
	a := &models.ApplicationForm{}

	if err := ctx.Bind(a); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(a); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	app, err := l.Manager.CreateApplication(a)
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
	a := &models.ApplicationForm{}

	if err := ctx.Bind(a); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(a); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	app, err := l.Manager.UpdateApplication(id, a)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to update the application")
	}

	return ctx.JSON(http.StatusOK, app)
}

func (l *Manage) AddMFA(ctx echo.Context) error {
	f := &models.MfaApplicationForm{}

	if err := ctx.Bind(f); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(f); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	app, err := l.Manager.AddMFA(f)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, "Unable to create the application")
	}

	return ctx.JSON(http.StatusOK, app)
}
