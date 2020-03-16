package api

import (
	"net/http"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/api/apierror"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/labstack/echo/v4"
)

func InitLogin(cfg *Server) error {
	ctl := &Login{cfg}

	cfg.Echo.POST("/api/login", ctl.login, apierror.Redirect("/error"))
	cfg.Echo.GET("/api/login", ctl.check)
	cfg.Echo.GET("/api/login/subject", ctl.subject)

	return nil
}

// Login is login controller
type Login struct {
	cfg *Server
}

func (ctl *Login) check(ctx echo.Context) error {
	form := new(models.Oauth2LoginForm)
	if err := ctx.Bind(form); err != nil {
		return apierror.InvalidRequest(err)
	}

	db := ctx.Get("database").(database.MgoSession)
	m := manager.NewOauthManager(db, ctl.cfg.Registry, ctl.cfg.SessionConfig, ctl.cfg.HydraConfig, ctl.cfg.ServerConfig, ctl.cfg.Recaptcha)

	_, _, _, url, err := m.CheckAuth(ctx, form)
	if err != nil {
		return err
	}

	if url != "" {
		return ctx.Redirect(http.StatusTemporaryRedirect, url)
	}

	return ctx.Redirect(http.StatusTemporaryRedirect, "/sign-in?login_challenge="+form.Challenge)
}

func (ctl *Login) login(ctx echo.Context) error {
	form := new(models.Oauth2LoginSubmitForm)

	if err := ctx.Bind(form); err != nil {
		return apierror.InvalidRequest(err)
	}
	if err := ctx.Validate(form); err != nil {
		return apierror.InvalidParameters(err)
	}

	db := ctx.Get("database").(database.MgoSession)
	m := manager.NewOauthManager(db, ctl.cfg.Registry, ctl.cfg.SessionConfig, ctl.cfg.HydraConfig, ctl.cfg.ServerConfig, ctl.cfg.Recaptcha)

	url, err := m.Auth(ctx, form)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{"url": url})
}

func (ctl *Login) subject(ctx echo.Context) error {
	var challenge = ctx.QueryParam("login_challenge")

	db := ctx.Get("database").(database.MgoSession)
	m := manager.NewOauthManager(db, ctl.cfg.Registry, ctl.cfg.SessionConfig, ctl.cfg.HydraConfig, ctl.cfg.ServerConfig, ctl.cfg.Recaptcha)

	user, err := m.FindPrevUser(challenge)
	if err != nil && err != mgo.ErrNotFound {
		return err
	}

	var email string
	var avatar string

	if user != nil {
		email = user.Email
		avatar = user.Picture
	}
	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"email":  email,
		"avatar": avatar,
	})
}
