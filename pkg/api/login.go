package api

import (
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	jwtverifier "github.com/ProtocolONE/authone-jwt-verifier-golang"
	"github.com/globalsign/mgo"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

func InitLogin(cfg *Server) error {
	cfg.Echo.GET("/login/form", loginPage)

	g := cfg.Echo.Group("/authorize", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(*mgo.Session)
			logger := c.Get("logger").(*zap.Logger)
			c.Set("login_manager", manager.NewLoginManager(db, logger, cfg.RedisHandler, cfg.Registry))

			return next(c)
		}
	})

	g.GET("/link", authorizeLink)
	g.GET("/result", authorizeResult)
	g.GET("", authorize)

	return nil
}

func authorize(ctx echo.Context) error {
	form := new(models.AuthorizeForm)
	m := ctx.Get("login_manager").(*manager.LoginManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "Authorize bind form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return ctx.HTML(http.StatusBadRequest, e.Message)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
			Error:   errors.Wrap(err, "Authorize validate form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return ctx.HTML(http.StatusBadRequest, e.Message)
	}

	str, err := m.Authorize(ctx, form)
	if err != nil {
		helper.SaveErrorLog(ctx, m.Logger, err)
		return ctx.HTML(http.StatusBadRequest, err.Message)
	}

	return ctx.Redirect(http.StatusMovedPermanently, str)
}

func authorizeResult(ctx echo.Context) error {
	form := new(models.AuthorizeResultForm)
	m := ctx.Get("login_manager").(*manager.LoginManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "AuthorizeResult bind form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
			"Result":  &manager.SocialAccountError,
			"Payload": map[string]interface{}{"code": e.Code, "message": e.Message},
		})
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
			Error:   errors.Wrap(err, "AuthorizeResult validate form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
			"Result":  &manager.SocialAccountError,
			"Payload": map[string]interface{}{"code": e.Code, "message": e.Message},
		})
	}

	t, err := m.AuthorizeResult(ctx, form)
	if err != nil {
		return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
			"Result":  &manager.SocialAccountError,
			"Payload": map[string]interface{}{"code": err.Code, "message": err.Message},
		})
	}

	return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
		"Result":  t.Result,
		"Payload": t.Payload,
	})
}

func authorizeLink(ctx echo.Context) error {
	form := new(models.AuthorizeLinkForm)
	m := ctx.Get("login_manager").(*manager.LoginManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "AuthorizeLink bind form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return helper.JsonError(ctx, e)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
			Error:   errors.Wrap(err, "AuthorizeLink validate form failed"),
		}
		helper.SaveErrorLog(ctx, m.Logger, e)
		return helper.JsonError(ctx, e)
	}

	url, err := m.AuthorizeLink(ctx, form)
	if err != nil {
		helper.SaveErrorLog(ctx, m.Logger, err)
		return helper.JsonError(ctx, err)
	}

	return ctx.JSON(http.StatusOK, map[string]string{"url": url})
}

func loginPage(ctx echo.Context) (err error) {
	form := new(models.LoginPageForm)
	logger := ctx.Get("logger").(*zap.Logger)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "Login bind form failed"),
		}
		helper.SaveErrorLog(ctx, logger, e)
		return ctx.HTML(http.StatusBadRequest, e.Message)
	}

	url, err := createAuthUrl(ctx, form)
	if err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: "Unable to authorize, please come back later",
			Error:   errors.Wrap(err, "Unable to create authenticate url"),
		}
		helper.SaveErrorLog(ctx, logger, e)
		return ctx.HTML(http.StatusInternalServerError, e.Message)
	}

	return ctx.Redirect(http.StatusMovedPermanently, url)
}

func createAuthUrl(ctx echo.Context, form *models.LoginPageForm) (string, error) {
	scopes := []string{"openid"}
	if form.Scopes != "" {
		scopes = strings.Split(form.Scopes, " ")
	}

	if form.RedirectUri == "" {
		form.RedirectUri = fmt.Sprintf("%s://%s/oauth2/callback", ctx.Scheme(), ctx.Request().Host)
	}

	settings := jwtverifier.Config{
		ClientID:     form.ClientID,
		ClientSecret: "",
		Scopes:       scopes,
		RedirectURL:  form.RedirectUri,
		Issuer:       fmt.Sprintf("%s://%s", ctx.Scheme(), ctx.Request().Host),
	}
	jwtv := jwtverifier.NewJwtVerifier(settings)

	return jwtv.CreateAuthUrl(form.State), nil
}
