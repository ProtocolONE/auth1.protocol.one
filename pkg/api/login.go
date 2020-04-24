package api

import (
	"net/http"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/api/apierror"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/globalsign/mgo"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/pkg/errors"
)

func InitLogin(cfg *Server) error {
	ctl := &Login{cfg}

	cfg.Echo.POST("/api/login", ctl.login)
	cfg.Echo.GET("/api/login", ctl.check, apierror.Redirect("/error"))
	cfg.Echo.GET("/api/login/hint", ctl.hint)
	cfg.Echo.GET("/api/logout", ctl.logout, apierror.Redirect("/error"))

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

func (ctl *Login) logout(ctx echo.Context) error {
	challenge := ctx.QueryParam("logout_challenge")

	r, err := ctl.cfg.Registry.HydraAdminApi().AcceptLogoutRequest(&admin.AcceptLogoutRequestParams{
		Context:         ctx.Request().Context(),
		LogoutChallenge: challenge,
	})
	if err != nil {
		return err
	}

	return ctx.Redirect(http.StatusTemporaryRedirect, r.Payload.RedirectTo)
}

func (ctl *Login) hint(ctx echo.Context) error {
	db := ctx.Get("database").(database.MgoSession)
	authLog := service.NewAuthLogService(db, nil)
	users := service.NewUserService(db)

	records, err := authLog.GetByDevice(service.GetDeviceID(ctx), 1, "")
	if err != nil {
		return err
	}

	var (
		email    string
		avatar   string
		username string
	)

	if len(records) > 0 {
		user, err := users.Get(records[0].UserID)
		if err != nil && err != mgo.ErrNotFound {
			return errors.Wrap(err, "failed to load user")
		}

		if user != nil {
			email = user.Email
			avatar = user.Picture
			username = user.Username
		}
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"username": username,
		"email":    email,
		"avatar":   avatar,
	})
}
