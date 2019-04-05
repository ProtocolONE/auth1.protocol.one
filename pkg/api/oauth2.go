package api

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

func InitOauth2(cfg *Server) error {
	g := cfg.Echo.Group("/oauth2", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(*mgo.Session)
			logger := c.Get("logger").(*zap.Logger)
			c.Set("oauth_manager", manager.NewOauthManager(db, logger, cfg.RedisHandler, cfg.SessionConfig, cfg.Registry))

			return next(c)
		}
	})

	g.GET("/login", oauthLogin)
	g.POST("/login", oauthLoginSubmit)
	g.GET("/consent", oauthConsent)
	g.POST("/consent", oauthConsentSubmit)
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
		m.Logger.Error(
			"Login page bind form failed",
			zap.Error(err),
		)
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	previousLogin := ""
	appID, user, url, err := m.CheckAuth(ctx, form)
	if err != nil {
		m.Logger.Error(
			"Error checking login request",
			zap.Error(err),
		)
		return ctx.HTML(http.StatusBadRequest, models.ErrorUnknownError)
	}
	if url != "" {
		return ctx.Redirect(http.StatusFound, url)
	}
	if user != nil {
		previousLogin = user.Email
	}

	return ctx.Render(http.StatusOK, "oauth_login.html", map[string]interface{}{
		"AuthDomain":    ctx.Scheme() + "://" + ctx.Request().Host,
		"Challenge":     form.Challenge,
		"ClientID":      appID,
		"PreviousLogin": previousLogin,
	})
}

func oauthLoginSubmit(ctx echo.Context) error {
	form := new(models.Oauth2LoginSubmitForm)
	m := ctx.Get("oauth_manager").(*manager.OauthManager)

	if err := ctx.Bind(form); err != nil {
		m.Logger.Error(
			"Login bind form failed",
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
		m.Logger.Error(
			"Login validate form failed",
			zap.Object("LoginForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	url, err := m.Auth(ctx, form)
	if err != nil {
		httpCode := http.StatusBadRequest
		code := BadRequiredCodeCommon
		message := fmt.Sprint(err)

		if err.GetHttpCode() != 0 {
			httpCode = err.GetHttpCode()
		}
		if err.GetCode() != "" {
			code = err.GetCode()
		}
		if err.GetMessage() != "" {
			message = err.GetMessage()
		}

		return ctx.JSON(httpCode, &models.CommonError{
			Code:    code,
			Message: message,
		})
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{"url": url})
}

func oauthConsent(ctx echo.Context) error {
	form := new(models.Oauth2ConsentForm)
	m := ctx.Get("oauth_manager").(*manager.OauthManager)

	if err := ctx.Bind(form); err != nil {
		m.Logger.Error(
			"Consent page bind form failed",
			zap.Error(err),
		)
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	url, err := m.Consent(ctx, form)
	if err != nil {
		m.Logger.Error(
			"Unable to load scopes",
			zap.Error(err),
		)
		return ctx.HTML(http.StatusBadRequest, models.ErrorUnknownError)
	}

	return ctx.Redirect(http.StatusFound, url)
}

func oauthConsentSubmit(ctx echo.Context) error {
	form := new(models.Oauth2ConsentSubmitForm)
	m := ctx.Get("oauth_manager").(*manager.OauthManager)

	if err := ctx.Bind(form); err != nil {
		m.Logger.Error(
			"Consent page bind form failed",
			zap.Error(err),
		)
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	url, err := m.ConsentSubmit(ctx, form)
	if err != nil {
		scopes, err := m.GetScopes()
		if err != nil {
			m.Logger.Error(
				"Unable to load scopes",
				zap.Error(err),
			)

			return ctx.HTML(http.StatusBadRequest, models.ErrorUnknownError)
		}

		return ctx.Render(http.StatusOK, "oauth_consent.html", map[string]interface{}{
			"Challenge": form.Challenge,
			"Scope":     scopes,
			"Error":     err.Error(),
		})
	}

	return ctx.Redirect(http.StatusFound, url)
}

func oauthIntrospect(ctx echo.Context) error {
	form := new(models.Oauth2IntrospectForm)
	m := ctx.Get("oauth_manager").(*manager.OauthManager)

	if err := ctx.Bind(form); err != nil {
		m.Logger.Error(
			"Introspect page bind form failed",
			zap.Error(err),
		)
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	token, err := m.Introspect(ctx, form)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, nil)
	}

	return ctx.JSON(http.StatusOK, token)
}

func oauthSignUp(ctx echo.Context) error {
	form := new(models.Oauth2SignUpForm)
	m := ctx.Get("oauth_manager").(*manager.OauthManager)

	if err := ctx.Bind(form); err != nil {
		m.Logger.Error(
			"SignUp bind form failed",
			zap.Error(err),
		)
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	url, err := m.SignUp(ctx, form)
	if err != nil {
		httpCode := http.StatusBadRequest
		code := BadRequiredCodeCommon
		message := fmt.Sprint(err)

		if err.GetHttpCode() != 0 {
			httpCode = err.GetHttpCode()
		}
		if err.GetCode() != "" {
			code = err.GetCode()
		}
		if err.GetMessage() != "" {
			message = err.GetMessage()
		}

		return ctx.JSON(httpCode, &models.CommonError{
			Code:    code,
			Message: message,
		})
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{"url": url})
}

func oauthCallback(ctx echo.Context) error {
	form := new(models.Oauth2CallBackForm)
	m := ctx.Get("oauth_manager").(*manager.OauthManager)

	if err := ctx.Bind(form); err != nil {
		m.Logger.Error(
			"Callback page bind form failed",
			zap.Error(err),
		)
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	response := m.CallBack(ctx, form)
	return ctx.Render(http.StatusOK, "oauth_callback.html", map[string]interface{}{
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
		m.Logger.Error(
			"Callback page bind form failed",
			zap.Error(err),
		)
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	url, err := m.Logout(ctx, form)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	if url != "" {
		return ctx.Redirect(http.StatusFound, url)
	}

	return ctx.Render(http.StatusOK, "oauth_logout.html", map[string]interface{}{})
}
