package api

import (
	"errors"
	"net/http"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/api/apierror"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/captcha"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/globalsign/mgo/bson"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra/sdk/go/hydra/client/admin"
)

func InitPasswordReset(cfg *Server) error {
	g := cfg.Echo.Group("/api", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(database.MgoSession)
			c.Set("manage_manager", manager.NewManageManager(db, cfg.Registry))
			c.Set("oauth_manager", manager.NewOauthManager(db, cfg.Registry, cfg.SessionConfig, cfg.HydraConfig, cfg.ServerConfig, cfg.Recaptcha))
			c.Set("password_manager", manager.NewChangePasswordManager(db, cfg.Registry, cfg.ServerConfig, cfg.MailTemplates))
			c.Set("recaptcha", cfg.Recaptcha)
			c.Set("registry", cfg.Registry)

			return next(c)
		}
	})

	g.POST("/password/reset", passwordReset)
	g.POST("/password/reset/link", passwordResetCheck)
	g.POST("/password/reset/set", passwordResetSet)

	return nil
}

// Password Reset

func passwordReset(ctx echo.Context) error {
	var r struct {
		CaptchaToken  string `query:"captchaToken" r:"captchaToken" validate:"required" json:"captchaToken"`
		CaptchaAction string `query:"captchaAction" r:"captchaAction" validate:"required" json:"captchaAction"`
		Challenge     string `query:"challenge" r:"challenge" validate:"required" json:"challenge"`
		Email         string `query:"email" r:"email" validate:"required" json:"email"`
	}

	if err := ctx.Bind(&r); err != nil {
		return apierror.InvalidRequest(err)
	}
	if err := ctx.Validate(r); err != nil {
		return apierror.InvalidParameters(err)
	}

	registry, ok := ctx.Get("registry").(service.InternalRegistry)
	if !ok {
		return errors.New("can't get some manager")
	}

	req, err := registry.HydraAdminApi().GetLoginRequest(&admin.GetLoginRequestParams{Challenge: r.Challenge, Context: ctx.Request().Context()})
	if err != nil {
		return apierror.InvalidChallenge
	}
	app, err := registry.ApplicationService().Get(bson.ObjectIdHex(req.Payload.Client.ClientID))
	if err != nil {
		return err
	}

	if app.RequiresCaptcha {
		recaptcha := ctx.Get("recaptcha").(*captcha.Recaptcha)
		ok, err := recaptcha.Verify(ctx.Request().Context(), r.CaptchaToken, r.CaptchaAction, "")
		if err != nil {
			return err
		}
		if !ok {
			return apierror.CaptchaRequired
		}
	}

	m, ok := ctx.Get("password_manager").(*manager.ChangePasswordManager)
	if !ok {
		return errors.New("can't get some manager")
	}

	form := &models.ChangePasswordStartForm{
		ClientID:  req.Payload.Client.ClientID,
		Email:     r.Email,
		Challenge: r.Challenge,
	}
	if err := m.ChangePasswordStart(form); err != nil {
		if err.Code == "email" {
			return apierror.EmailNotFound
		}
		ctx.Logger().Error(err.Error())
		return err
	}

	return ctx.JSON(http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func passwordResetCheck(ctx echo.Context) error {
	var form struct {
		Token string `query:"token" form:"token" validate:"required" json:"token"`
	}

	if err := ctx.Bind(&form); err != nil {
		return apierror.InvalidRequest(err)
	}
	if err := ctx.Validate(form); err != nil {
		return apierror.InvalidParameters(err)
	}

	m := ctx.Get("password_manager").(*manager.ChangePasswordManager)

	email, err := m.ChangePasswordCheck(form.Token)
	if err != nil {
		return apierror.TokenOutdated
	}

	return ctx.JSON(http.StatusOK, map[string]string{
		"email": email,
	})
}

func passwordResetSet(ctx echo.Context) error {
	var form struct {
		Token    string `query:"token" form:"token" validate:"required" json:"token"`
		Password string `query:"password" form:"password" validate:"required" json:"password"`
	}

	if err := ctx.Bind(&form); err != nil {
		return apierror.InvalidRequest(err)
	}
	if err := ctx.Validate(form); err != nil {
		return apierror.InvalidParameters(err)
	}

	registry, ok := ctx.Get("registry").(service.InternalRegistry)
	if !ok {
		return errors.New("can't get some manager")
	}

	m, ok := ctx.Get("password_manager").(*manager.ChangePasswordManager)
	if !ok {
		return errors.New("can't get some manager")
	}

	oauthManager, ok := ctx.Get("oauth_manager").(*manager.OauthManager)
	if !ok {
		return errors.New("can't get some manager")
	}

	ts := &models.ChangePasswordTokenSource{}
	if err := registry.OneTimeTokenService().Get(form.Token, ts); err != nil {
		return apierror.InvalidToken
	}

	f := &models.ChangePasswordVerifyForm{
		ClientID:       ts.ClientID,
		Token:          form.Token,
		Password:       form.Password,
		PasswordRepeat: form.Password,
	}
	if err := m.ChangePasswordVerify(f); err != nil {
		return err
	}

	// todo: logout & drop sessions

	// login
	loginForm := new(models.Oauth2LoginSubmitForm)
	loginForm.Challenge = ts.Challenge
	loginForm.Email = ts.Email
	loginForm.Password = form.Password

	url, err := oauthManager.Auth(ctx, loginForm)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{"url": url})
}
