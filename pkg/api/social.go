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
	cfg.Echo.GET("/api/providers/:name/check", s.Check)
	cfg.Echo.GET("/api/providers/:name/confirm", s.Confirm)
	cfg.Echo.GET("/api/providers/ws", s.WS)
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

	url, err := m.SignUp(ctx, form)
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
		launcher  = ctx.QueryParam("launcher")
		domain    = fmt.Sprintf("%s://%s", ctx.Scheme(), ctx.Request().Host)
	)

	db := ctx.Get("database").(database.MgoSession)
	m := manager.NewLoginManager(db, s.registry)

	url, err := m.ForwardUrl(challenge, name, domain, launcher)
	if err != nil {
		return err
	}

	// if launcher == true, then store challenge and options
	if launcher == "true" {
		err := s.registry.LauncherTokenService().Set(challenge, models.LauncherToken{
			Name:   name,
			Status: "in_progress",
		}, &models.LauncherTokenSettings{
			TTL: 600,
		})
		if err != nil {
			return err
		}
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

	// if launcher token with login_challenge key exists, then return to launcher
	state, err := manager.DecodeState(req.State)
	if err != nil {
		return err
	}
	if state.Launcher == "true" {
		t := &models.LauncherToken{}
		err := s.registry.LauncherTokenService().Get(state.Challenge, t)
		if err != nil {
			return err
		}
		t.URL = url
		err = s.registry.LauncherTokenService().Set(state.Challenge, t, &models.LauncherTokenSettings{TTL: 600})
		if err != nil {
			return err
		}
		return ctx.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("/social-sign-in-confirm?login_challenge=%s&name=%s", state.Challenge, name))
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

func (s *Social) Check(ctx echo.Context) error {
	type response struct {
		Status string `json:"status"`
		URL    string `json:"url,omitempty"`
	}

	var (
		name           = ctx.Param("name")
		loginChallenge = ctx.QueryParam("login_challenge")
		t              = &models.LauncherToken{}
	)

	err := s.registry.LauncherTokenService().Get(loginChallenge, t)
	if err != nil {
		ctx.Logger().Error(err.Error())
		return ctx.JSON(http.StatusOK, response{
			Status: "expired",
		})
	}

	if t.Name != name {
		return ctx.JSON(http.StatusOK, response{
			Status: "expired",
		})
	}

	return ctx.JSON(http.StatusOK, response{
		Status: t.Status,
		URL:    t.URL,
	})
}

func (s *Social) WS(ctx echo.Context) error {
	conn, err := service.Upgrader.Upgrade(ctx.Response(), ctx.Request(), nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	loginChallenge := ctx.QueryParam("login_challenge")

	srv := s.registry.LauncherServer()
	c := service.NewLauncherClient(loginChallenge, conn, srv)

	srv.Register(c)

	go c.Read()
	go c.Write()

	// wait till the ws will be closed
	c.Await()

	return nil
}

func (s *Social) Confirm(ctx echo.Context) error {
	var (
		challenge = ctx.QueryParam("login_challenge")
	)

	t := &models.LauncherToken{}
	err := s.registry.LauncherTokenService().Get(challenge, t)
	if err != nil {
		return err
	}

	s.registry.LauncherServer().Success(challenge, t.URL)

	t.Status = "success"
	err = s.registry.LauncherTokenService().Set(challenge, t, &models.LauncherTokenSettings{TTL: 600})
	if err != nil {
		return err
	}
	return ctx.JSON(http.StatusOK, map[string]string{
		"status": "success",
	})
}
