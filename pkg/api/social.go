package api

import (
	"fmt"
	"net/http"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/api/apierror"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/captcha"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/labstack/echo/v4"
)

func InitSocial(cfg *Server) error {
	s := NewSocial(cfg)

	cfg.Echo.GET("/api/providers", s.List)
	cfg.Echo.GET("/api/providers/:name/profile", s.Profile)
	cfg.Echo.POST("/api/providers/:name/link", s.Link)
	cfg.Echo.POST("/api/providers/:name/signup", s.Signup)
	// redirect based apis
	cfg.Echo.GET("/api/providers/:name/forward", s.Forward, apierror.Redirect("/error"))
	cfg.Echo.GET("/api/providers/:name/callback", s.Callback, apierror.Redirect("/error"))

	return nil
}

type Social struct {
	registry service.InternalRegistry

	HydraConfig   *config.Hydra
	SessionConfig *config.Session
	ServerConfig  *config.Server
	Recaptcha     *captcha.Recaptcha
}

func NewSocial(cfg *Server) *Social {
	return &Social{
		registry:      cfg.Registry,
		HydraConfig:   cfg.HydraConfig,
		SessionConfig: cfg.SessionConfig,
		ServerConfig:  cfg.ServerConfig,
	}
}

type ProviderInfo struct {
	Name string `json:"name"`
	// Url  string `json:"url"`
}

func (s *Social) Signup(ctx echo.Context) error {
	form := new(models.Oauth2SignUpForm)
	var (
		db = ctx.Get("database").(database.MgoSession)
		m  = manager.NewOauthManager(db, s.registry, s.SessionConfig, s.HydraConfig, s.ServerConfig, s.Recaptcha)
	)

	if err := ctx.Bind(form); err != nil {
		return apierror.InvalidRequest(err)
	}

	url, err := m.SignUp(ctx, form, GetDeviceID(ctx))
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{"url": url})
}

func (s *Social) Link(ctx echo.Context) error {
	var (
		db = ctx.Get("database").(database.MgoSession)
		m  = manager.NewOauthManager(db, s.registry, s.SessionConfig, s.HydraConfig, s.ServerConfig, s.Recaptcha)
	)

	var form = new(models.Oauth2LoginSubmitForm)
	if err := ctx.Bind(form); err != nil {
		return apierror.InvalidRequest(err)
	}
	if err := ctx.Validate(form); err != nil {
		return apierror.InvalidParameters(err)
	}

	url, err := m.Auth(ctx, form)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{"url": url})

}

func (s *Social) List(ctx echo.Context) error {
	var challenge = ctx.QueryParam("login_challenge")

	db := ctx.Get("database").(database.MgoSession)
	m := manager.NewLoginManager(db, s.registry)

	ips, err := m.Providers(challenge)
	if err != nil {
		return err
	}

	var res []ProviderInfo
	for i := range ips {
		res = append(res, ProviderInfo{
			Name: ips[i].Name,
			// Url:  "",
		})
	}

	return ctx.JSON(http.StatusOK, res)
}

func (s *Social) Forward(ctx echo.Context) error {
	var (
		name      = ctx.Param("name")
		challenge = ctx.QueryParam("login_challenge")
		domain    = fmt.Sprintf("%s://%s", ctx.Scheme(), ctx.Request().Host)
	)

	db := ctx.Get("database").(database.MgoSession)
	m := manager.NewLoginManager(db, s.registry)

	url, err := m.ForwardUrl(challenge, name, domain)
	if err != nil {
		return err
	}

	return ctx.Redirect(http.StatusPermanentRedirect, url)
}

func (s *Social) Callback(ctx echo.Context) error {
	var (
		name = ctx.Param("name")
		req  struct {
			Code  string `query:"code"`
			State string `query:"state"`
			Error string `query:"error"`
		}
		domain = fmt.Sprintf("%s://%s", ctx.Scheme(), ctx.Request().Host)
	)

	db := ctx.Get("database").(database.MgoSession)
	m := manager.NewLoginManager(db, s.registry)

	if err := ctx.Bind(&req); err != nil {
		return apierror.InvalidRequest(err)
	}

	if req.Error != "" {
		s, err := manager.DecodeState(req.State)
		if err != nil {
			return err
		}
		return ctx.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("/sign-in?login_challenge=%s", s.Challenge))
	}

	url, err := m.Callback(ctx, name, req.Code, req.State, domain)
	if err != nil {
		return err
	}

	return ctx.Redirect(http.StatusTemporaryRedirect, url)
}

func (s *Social) Profile(ctx echo.Context) error {
	var token = ctx.QueryParam("token")

	db := ctx.Get("database").(database.MgoSession)
	m := manager.NewLoginManager(db, s.registry)

	profile, err := m.Profile(token)
	if err != nil {
		return err
	}

	profile.HideSensitive()

	return ctx.JSON(http.StatusOK, profile)

}
