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

type Oauth2 struct {
	Manager *manager.OauthManager
	Http    *echo.Echo
	logger  *zap.Logger
}

func InitOauth2(cfg Config) error {
	route := &Oauth2{
		Manager: manager.NewOauthManager(cfg.Logger, cfg.Database, cfg.Redis, cfg.Hydra, cfg.Session),
		Http:    cfg.Echo,
		logger:  cfg.Logger,
	}

	cfg.Echo.GET("/oauth2/login", route.oauthLogin)
	cfg.Echo.POST("/oauth2/login", route.oauthLoginSubmit)
	cfg.Echo.GET("/oauth2/consent", route.oauthConsent)
	cfg.Echo.POST("/oauth2/consent", route.oauthConsentSubmit)
	cfg.Echo.POST("/oauth2/signup", route.oauthSignUp)
	cfg.Echo.POST("/oauth2/introspect", route.oauthIntrospect)
	cfg.Echo.GET("/oauth2/callback", route.oauthCallback)

	return nil
}

func (l *Oauth2) oauthLogin(ctx echo.Context) error {
	form := new(models.Oauth2LoginForm)
	if err := ctx.Bind(form); err != nil {
		l.logger.Error("Login page bind form failed", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	if url, _ := l.Manager.CheckAuth(ctx, form); url != "" {
		return ctx.Redirect(http.StatusPermanentRedirect, url)
	}

	csrf, err := l.Manager.CreateCsrfSession(ctx)
	if err != nil {
		l.logger.Error("Error saving session", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorUnknownError)
	}

	return ctx.Render(http.StatusOK, "oauth_login.html", map[string]interface{}{
		"AuthDomain": ctx.Scheme() + "://" + ctx.Request().Host,
		"Challenge":  form.Challenge,
		"Csrf":       csrf,
	})
}

func (l *Oauth2) oauthLoginSubmit(ctx echo.Context) error {
	form := new(models.Oauth2LoginSubmitForm)
	if err := ctx.Bind(form); err != nil {
		l.logger.Error("Login bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}
	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
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

	url, err := l.Manager.Auth(ctx, form)
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
		return helper.NewErrorResponse(ctx, httpCode, code, message)
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{"url": url})
}

func (l *Oauth2) oauthConsent(ctx echo.Context) error {
	form := new(models.Oauth2ConsentForm)
	if err := ctx.Bind(form); err != nil {
		l.logger.Error("Consent page bind form failed", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	url, err := l.Manager.Consent(ctx, form)
	if err != nil {
		l.logger.Error("Unable to load scopes", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorUnknownError)
	}

	return ctx.Redirect(http.StatusPermanentRedirect, url)
}

func (l *Oauth2) oauthConsentSubmit(ctx echo.Context) error {
	form := new(models.Oauth2ConsentSubmitForm)
	if err := ctx.Bind(form); err != nil {
		l.logger.Error("Consent page bind form failed", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	url, err := l.Manager.ConsentSubmit(ctx, form)
	if err != nil {
		scopes, err := l.Manager.GetScopes()
		if err != nil {
			l.logger.Error("Unable to load scopes", zap.Error(err))
			return ctx.HTML(http.StatusBadRequest, models.ErrorUnknownError)
		}

		return ctx.Render(http.StatusOK, "oauth_consent.html", map[string]interface{}{
			"Challenge": form.Challenge,
			"Csrf":      form.Csrf,
			"Scope":     scopes,
			"Error":     err.Error(),
		})
	}

	return ctx.Redirect(http.StatusPermanentRedirect, url)
}

func (l *Oauth2) oauthIntrospect(ctx echo.Context) error {
	form := new(models.Oauth2IntrospectForm)
	if err := ctx.Bind(form); err != nil {
		l.logger.Error("Introspect page bind form failed", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	token, err := l.Manager.Introspect(ctx, form)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, nil)
	}

	return ctx.JSON(http.StatusOK, token)
}

func (l *Oauth2) oauthSignUp(ctx echo.Context) error {
	form := new(models.Oauth2SignUpForm)
	if err := ctx.Bind(form); err != nil {
		l.logger.Error("SigUp bind form failed", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	url, err := l.Manager.SignUp(ctx, form)
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
		return helper.NewErrorResponse(ctx, httpCode, code, message)
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{"url": url})
}

func (l *Oauth2) oauthCallback(ctx echo.Context) error {
	form := new(models.Oauth2CallBackForm)
	if err := ctx.Bind(form); err != nil {
		l.logger.Error("Callback page bind form failed", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	response := l.Manager.CallBack(ctx, form)
	return ctx.Render(http.StatusOK, "oauth_callback.html", map[string]interface{}{
		"Success":      response.Success,
		"ErrorMessage": response.ErrorMessage,
		"AccessToken":  response.AccessToken,
		"ExpiresIn":    response.ExpiresIn,
		"IdToken":      response.IdToken,
	})
}
