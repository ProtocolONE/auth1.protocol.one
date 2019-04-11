package api

import (
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"net/http"
)

func InitOauth2(cfg *Server) error {
	g := cfg.Echo.Group("/oauth2", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(*mgo.Session)
			c.Set("oauth_manager", manager.NewOauthManager(db, cfg.RedisHandler, cfg.Registry, cfg.SessionConfig, cfg.HydraConfig))

			return next(c)
		}
	})

	g.GET("/login", oauthLogin)
	g.POST("/login", oauthLoginSubmit)
	g.GET("/consent", oauthConsent)
	g.POST("/signup", oauthSignUp)
	g.POST("/introspect", oauthIntrospect)
	g.GET("/callback", oauthCallback)
	g.GET("/logout", oauthLogout)

	return nil
}

func oauthLogin(ctx echo.Context) error {
	form := new(models.Oauth2LoginForm)
	m := ctx.Get("oauth_manager").(*manager.OauthManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "Oauth2 login bind form failed"),
		}
		return ctx.HTML(http.StatusBadRequest, e.Message)
	}

	previousLogin := ""
	appID, user, providers, url, err := m.CheckAuth(ctx, form)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, err.Message)
	}
	if url != "" {
		return ctx.Redirect(http.StatusFound, url)
	}
	if user != nil {
		previousLogin = user.Email
	}

	socProviders := map[int]interface{}{}
	if len(providers) > 0 {
		for i, provider := range providers {
			socProviders[i] = map[string]interface{}{
				"Name":        provider.Name,
				"DisplayName": provider.DisplayName,
			}
		}
	}

	return ctx.Render(http.StatusOK, "oauth_login.html", map[string]interface{}{
		"AuthDomain":    ctx.Scheme() + "://" + ctx.Request().Host,
		"Challenge":     form.Challenge,
		"ClientID":      appID,
		"PreviousLogin": previousLogin,
		"SocProviders":  socProviders,
	})
}

func oauthLoginSubmit(ctx echo.Context) error {
	form := new(models.Oauth2LoginSubmitForm)
	m := ctx.Get("oauth_manager").(*manager.OauthManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "Oauth submit bind form failed"),
		}
		return helper.JsonError(ctx, e)
	}
	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
			Error:   errors.Wrap(err, "Oauth submit validate form failed"),
		}
		return helper.JsonError(ctx, e)
	}

	url, err := m.Auth(ctx, form)
	if err != nil {
		return helper.JsonError(ctx, err)
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{"url": url})
}

func oauthConsent(ctx echo.Context) error {
	form := new(models.Oauth2ConsentForm)
	m := ctx.Get("oauth_manager").(*manager.OauthManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "Consent bind form failed"),
		}
		return ctx.HTML(http.StatusBadRequest, e.Message)
	}

	url, err := m.Consent(ctx, form)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, err.Message)
	}

	return ctx.Redirect(http.StatusFound, url)
}

func oauthIntrospect(ctx echo.Context) error {
	form := new(models.Oauth2IntrospectForm)
	m := ctx.Get("oauth_manager").(*manager.OauthManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "Introspect bind form failed"),
		}
		return helper.JsonError(ctx, e)
	}

	token, err := m.Introspect(ctx, form)
	if err != nil {
		return helper.JsonError(ctx, err)
	}

	return ctx.JSON(http.StatusOK, token)
}

func oauthSignUp(ctx echo.Context) error {
	form := new(models.Oauth2SignUpForm)
	m := ctx.Get("oauth_manager").(*manager.OauthManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "SignUp bind form failed"),
		}
		return helper.JsonError(ctx, e)
	}

	url, err := m.SignUp(ctx, form)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, err)
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{"url": url})
}

func oauthCallback(ctx echo.Context) error {
	form := new(models.Oauth2CallBackForm)
	m := ctx.Get("oauth_manager").(*manager.OauthManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "Callback bind form failed"),
		}
		return ctx.HTML(http.StatusBadRequest, e.Message)
	}

	code := http.StatusOK
	response, err := m.CallBack(ctx, form)
	if err != nil {
		code = http.StatusBadRequest
	}
	return ctx.Render(code, "oauth_callback.html", map[string]interface{}{
		"Success":      response.Success,
		"ErrorMessage": response.ErrorMessage,
		"AccessToken":  response.AccessToken,
		"ExpiresIn":    response.ExpiresIn,
		"IdToken":      response.IdToken,
	})
}

func oauthLogout(ctx echo.Context) error {
	form := new(models.Oauth2LogoutForm)
	m := ctx.Get("oauth_manager").(*manager.OauthManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
			Error:   errors.Wrap(err, "Logout bind form failed"),
		}
		return ctx.HTML(http.StatusBadRequest, e.Message)
	}

	url, err := m.Logout(ctx, form)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, err.Message)
	}

	if url != "" {
		return ctx.Redirect(http.StatusFound, url)
	}

	return ctx.Render(http.StatusOK, "oauth_logout.html", map[string]interface{}{})
}
