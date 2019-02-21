package route

import (
	"auth-one-api/pkg/manager"
	"auth-one-api/pkg/models"
	"github.com/labstack/echo"
	"go.uber.org/zap"
	"net/http"
)

type Oauth struct {
	Manager *manager.OauthManager
	Http    *echo.Echo
	logger  *zap.Logger
}

func InitOauth(cfg Config) error {
	route := &Oauth{
		Manager: manager.NewOauthManager(cfg.Logger, cfg.Database, cfg.Redis, cfg.Hydra, cfg.Session),
		Http:    cfg.Echo,
		logger:  cfg.Logger,
	}

	cfg.Echo.GET("/oauth/login", route.oauthLogin)
	cfg.Echo.POST("/oauth/login", route.oauthLoginSubmit)
	cfg.Echo.GET("/oauth/consent", route.oauthConsent)
	cfg.Echo.POST("/oauth/consent", route.oauthConsentSubmit)

	return nil
}

func (l *Oauth) oauthLogin(ctx echo.Context) error {
	form := new(models.OauthLoginForm)
	if err := ctx.Bind(form); err != nil {
		l.logger.Error("Login page bind form failed", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	csrf, err := l.Manager.CreateCsrfSession(ctx)
	if err != nil {
		l.logger.Error("Error saving session", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorUnknownError)
	}

	return ctx.Render(http.StatusOK, "oauth_login.html", map[string]interface{}{
		"Challenge": form.Challenge,
		"Csrf":      csrf,
	})
}

func (l *Oauth) oauthLoginSubmit(ctx echo.Context) error {
	form := new(models.OauthLoginSubmitForm)
	if err := ctx.Bind(form); err != nil {
		l.logger.Error("Login page bind form failed", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	url, err := l.Manager.Auth(ctx, form)
	if err != nil {
		csrf, e := l.Manager.CreateCsrfSession(ctx)
		if e != nil {
			l.logger.Error("Error saving session", zap.Error(e))
			return ctx.HTML(http.StatusBadRequest, models.ErrorUnknownError)
		}

		return ctx.Render(http.StatusOK, "oauth_login.html", map[string]interface{}{
			"Challenge": form.Challenge,
			"Csrf":      csrf,
			"Error":     err.Error(),
		})
	}

	return ctx.Redirect(http.StatusPermanentRedirect, url)
}

func (l *Oauth) oauthConsent(ctx echo.Context) error {
	form := new(models.OauthConsentForm)
	if err := ctx.Bind(form); err != nil {
		l.logger.Error("Consent page bind form failed", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	csrf, err := l.Manager.CreateCsrfSession(ctx)
	if err != nil {
		l.logger.Error("Error saving session", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorUnknownError)
	}

	scopes, err := l.Manager.Consent(ctx, form)
	if err != nil {
		l.logger.Error("Unable to load scopes", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorUnknownError)
	}

	return ctx.Render(http.StatusOK, "oauth_consent.html", map[string]interface{}{
		"Challenge": form.Challenge,
		"Csrf":      csrf,
		"Scopes":    scopes,
	})
}

func (l *Oauth) oauthConsentSubmit(ctx echo.Context) error {
	form := new(models.OauthConsentSubmitForm)
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
