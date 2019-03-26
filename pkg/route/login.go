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
	Login struct {
		Manager *manager.LoginManager
		Http    *echo.Echo
		logger  *zap.Logger
	}
)

func InitLogin(cfg Config) error {
	route := &Login{
		Manager: manager.NewLoginManager(cfg.Logger, cfg.Database, cfg.Redis, cfg.Session, cfg.Hydra),
		Http:    cfg.Echo,
		logger:  cfg.Logger,
	}

	cfg.Echo.GET("/authorize/link", route.AuthorizeLink)
	cfg.Echo.GET("/authorize/result", route.AuthorizeResult)
	cfg.Echo.GET("/authorize", route.Authorize)
	cfg.Echo.GET("/login/form", route.LoginPage)
	cfg.Echo.GET("/login/ott", route.LoginByOTT)

	return nil
}

func (l *Login) Authorize(ctx echo.Context) error {
	form := new(models.AuthorizeForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("Authorize bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
			"Authorize validate form failed",
			zap.Object("AuthorizeForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	str, err := l.Manager.Authorize(ctx, form)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, err.GetMessage())
	}

	return ctx.Redirect(http.StatusMovedPermanently, str)
}

func (l *Login) AuthorizeResult(ctx echo.Context) error {
	form := new(models.AuthorizeResultForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("AuthorizeResult bind form failed", zap.Error(err))

		return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
			"Result":  &manager.SocialAccountError,
			"Payload": map[string]interface{}{"code": BadRequiredCodeCommon, "message": models.ErrorInvalidRequestParameters},
		})
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
			"AuthorizeResult validate form failed",
			zap.Object("AuthorizeResultForm", form),
			zap.Error(err),
		)

		return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
			"Result":  &manager.SocialAccountError,
			"Payload": map[string]interface{}{"code": fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()), "message": models.ErrorRequiredField},
		})
	}

	t, err := l.Manager.AuthorizeResult(ctx, form)
	if err != nil {
		return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
			"Result":  &manager.SocialAccountError,
			"Payload": map[string]interface{}{"code": UnknownErrorCode, "message": err.GetMessage()},
		})
	}

	return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
		"Result":  t.Result,
		"Payload": t.Payload,
	})
}

func (l *Login) AuthorizeLink(ctx echo.Context) error {
	form := new(models.AuthorizeLinkForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("AuthorizeLink bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
			"AuthorizeLink validate form failed",
			zap.Object("AuthorizeLinkForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	url, err := l.Manager.AuthorizeLink(ctx, form)
	if err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			err.GetCode(),
			err.GetMessage(),
		)
	}

	return ctx.JSON(http.StatusOK, map[string]string{"url": url})
}

func (l *Login) LoginPage(ctx echo.Context) (err error) {
	form := new(models.LoginPageForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("Login page bind form failed", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	url, err := l.Manager.CreateAuthUrl(ctx, form)
	if err != nil {
		return ctx.HTML(http.StatusInternalServerError, "Unable to authorize, please come back later")
	}

	return ctx.Redirect(http.StatusMovedPermanently, url)
}

func (l *Login) LoginByOTT(ctx echo.Context) error {
	form := new(models.OneTimeTokenForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("TokenOTT bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
			"TokenOTT bind validate failed",
			zap.Object("OneTimeTokenForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	token, e := l.Manager.LoginByOTT(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}
