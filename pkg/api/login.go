package api

import (
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	jwtverifier "github.com/ProtocolONE/authone-jwt-verifier-golang"
	"github.com/labstack/echo/v4"
	"net/http"
	"strings"
)

func InitLogin(cfg *Server) error {
	cfg.Echo.GET("/login/form", loginPage)

	g := cfg.Echo.Group("/authorize", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(database.Session)
			c.Set("login_manager", manager.NewLoginManager(db, cfg.Registry))

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
		ctx.Error(err)
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	if err := ctx.Validate(form); err != nil {
		ctx.Error(err)
		return ctx.HTML(http.StatusBadRequest, models.ErrorRequiredField)
	}

	str, err := m.Authorize(ctx, form)
	if err != nil {
		ctx.Error(err.Err)
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
		}
		ctx.Error(err)
		return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
			"Result":  &manager.SocialAccountError,
			"Payload": map[string]interface{}{"code": e.Code, "message": e.Message},
		})
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
		}
		ctx.Error(err)
		return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
			"Result":  &manager.SocialAccountError,
			"Payload": map[string]interface{}{"code": e.Code, "message": e.Message},
		})
	}

	t, err := m.AuthorizeResult(ctx, form)
	if err != nil {
		ctx.Error(err.Err)
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

	url, err := m.AuthorizeLink(ctx, form)
	if err != nil {
		ctx.Error(err.Err)
		return helper.JsonError(ctx, err)
	}

	return ctx.JSON(http.StatusOK, map[string]string{"url": url})
}

func loginPage(ctx echo.Context) (err error) {
	form := new(models.LoginPageForm)

	if err := ctx.Bind(form); err != nil {
		ctx.Error(err)
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	url, err := createAuthUrl(ctx, form)
	if err != nil {
		ctx.Error(err)
		return ctx.HTML(http.StatusInternalServerError, "Unable to authorize, please come back later")
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
