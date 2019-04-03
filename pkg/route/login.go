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

func InitLogin(cfg Config) error {
	cfg.Echo.GET("/login/form", loginPage)

	g := cfg.Echo.Group("/authorize", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(*mgo.Session)
			c.Set("login_manager", manager.NewLoginManager(db, cfg.Redis, cfg.Hydra))

			return next(c)
		}
	})

	g.GET("/link", authorizeLink)
	g.GET("/result", authorizeResult)
	g.GET("/", authorize)

	return nil
}

func authorize(ctx echo.Context) error {
	form := new(models.AuthorizeForm)

	if err := ctx.Bind(form); err != nil {
		zap.L().Error(
			"Authorize bind form failed",
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
			"Authorize validate form failed",
			zap.Object("AuthorizeForm", form),
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

	m := ctx.Get("login_manager").(*manager.LoginManager)
	str, err := m.Authorize(ctx, form)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, err.GetMessage())
	}

	return ctx.Redirect(http.StatusMovedPermanently, str)
}

func authorizeResult(ctx echo.Context) error {
	form := new(models.AuthorizeResultForm)

	if err := ctx.Bind(form); err != nil {
		zap.L().Error(
			"AuthorizeResult bind form failed",
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
			"Result":  &manager.SocialAccountError,
			"Payload": map[string]interface{}{"code": BadRequiredCodeCommon, "message": models.ErrorInvalidRequestParameters},
		})
	}

	if err := ctx.Validate(form); err != nil {
		zap.L().Error(
			"AuthorizeResult validate form failed",
			zap.Object("AuthorizeResultForm", form),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
			"Result":  &manager.SocialAccountError,
			"Payload": map[string]interface{}{"code": fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()), "message": models.ErrorRequiredField},
		})
	}

	m := ctx.Get("login_manager").(*manager.LoginManager)
	t, err := m.AuthorizeResult(ctx, form)
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

func authorizeLink(ctx echo.Context) error {
	form := new(models.AuthorizeLinkForm)

	if err := ctx.Bind(form); err != nil {
		zap.L().Error(
			"AuthorizeLink bind form failed",
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
			"AuthorizeLink validate form failed",
			zap.Object("AuthorizeLinkForm", form),
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

	m := ctx.Get("login_manager").(*manager.LoginManager)
	url, err := m.AuthorizeLink(ctx, form)
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

func loginPage(ctx echo.Context) (err error) {
	form := new(models.LoginPageForm)

	if err := ctx.Bind(form); err != nil {
		zap.L().Error(
			"Login page bind form failed",
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	m := ctx.Get("login_manager").(*manager.LoginManager)
	url, err := m.CreateAuthUrl(ctx, form)
	if err != nil {
		return ctx.HTML(http.StatusInternalServerError, "Unable to authorize, please come back later")
	}

	return ctx.Redirect(http.StatusMovedPermanently, url)
}
