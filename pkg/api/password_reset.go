package api

import (
	"context"
	"net/http"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/api/apierror"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/appcore/log"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/captcha"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/webhooks"
	
	"github.com/globalsign/mgo/bson"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func InitPasswordReset(cfg *Server) error {
	pr := NewPasswordReset(cfg)

	g := cfg.Echo.Group("/api", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(database.MgoSession)
			c.Set("manage_manager", manager.NewManageManager(db, cfg.Registry))
			c.Set("password_manager", manager.NewChangePasswordManager(db, cfg.Registry, cfg.ServerConfig, cfg.MailTemplates))

			return next(c)
		}
	})

	g.POST("/password/reset", pr.PasswordReset)
	g.POST("/password/reset/link", pr.PasswordResetLink)
	g.POST("/password/reset/set", pr.PasswordResetSet)

	return nil
}

type PasswordReset struct {
	Registry  service.InternalRegistry
	Recaptcha *captcha.Recaptcha
	WebHooks  *webhooks.WebHooks
}

func NewPasswordReset(cfg *Server) *PasswordReset {
	return &PasswordReset{
		Registry:  cfg.Registry,
		Recaptcha: cfg.Recaptcha,
		WebHooks:  cfg.WebHooks,
	}
}

// Password Reset

func (pr *PasswordReset) PasswordReset(ctx echo.Context) error {
	var r struct {
		CaptchaToken  string `query:"captchaToken" r:"captchaToken" validate:"required" json:"captchaToken"`
		CaptchaAction string `query:"captchaAction" r:"captchaAction" json:"captchaAction"`
		Challenge     string `query:"challenge" r:"challenge" validate:"required" json:"challenge"`
		Email         string `query:"email" r:"email" validate:"required" json:"email"`
	}

	if err := ctx.Bind(&r); err != nil {
		return apierror.InvalidRequest(err)
	}
	if err := ctx.Validate(r); err != nil {
		return apierror.InvalidParameters(err)
	}

	req, err := pr.Registry.HydraAdminApi().GetLoginRequest(&admin.GetLoginRequestParams{LoginChallenge: r.Challenge, Context: ctx.Request().Context()})

	if err != nil {
		return apierror.InvalidChallenge
	}
	app, err := pr.Registry.ApplicationService().Get(bson.ObjectIdHex(req.Payload.Client.ClientID))
	if err != nil {
		return err
	}

	space, err := pr.Registry.Spaces().FindByID(ctx.Request().Context(), entity.SpaceID(app.SpaceId.Hex()))
	if err != nil {
		return  errors.Wrap(err, "unable to load space")
	}

	if space.RequiresCaptcha {
		ok, err := pr.Recaptcha.Verify(ctx.Request().Context(), r.CaptchaToken, r.CaptchaAction, ctx.RealIP())
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
		Subject:   req.Payload.Subject,
		ClientID:  req.Payload.Client.ClientID,
		Email:     r.Email,
		Challenge: r.Challenge,
	}
	if err := m.ChangePasswordStart(form); err != nil {
		if err.Code == "email" {
			return apierror.EmailNotFound
		}
		return err
	}

	return ctx.JSON(http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func (pr *PasswordReset) PasswordResetLink(ctx echo.Context) error {
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

func (pr *PasswordReset) PasswordResetSet(ctx echo.Context) error {
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

	m, ok := ctx.Get("password_manager").(*manager.ChangePasswordManager)
	if !ok {
		return errors.New("can't get some manager")
	}

	ts := &models.ChangePasswordTokenSource{}
	if err := pr.Registry.OneTimeTokenService().Get(form.Token, ts); err != nil {
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

	rctx := ctx.Request().Context()

	// revoke consent sessions & revoke auth sessions
	_, err := pr.Registry.HydraAdminApi().RevokeConsentSessions(&admin.RevokeConsentSessionsParams{
		Subject: ts.Subject,
		Context: rctx,
	})
	if err != nil {
		log.Error(rctx, "failed revoke consent sessions", zap.Error(err))
	}

	_, err = pr.Registry.HydraAdminApi().RevokeAuthenticationSession(&admin.RevokeAuthenticationSessionParams{
		Subject: ts.Subject,
		Context: rctx,
	})
	if err != nil {
		log.Error(rctx, "failed revoke auth session", zap.Error(err))
	}

	pr.userLogoutWebHook(rctx, ts)

	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"status": "ok",
	})
}

func (pr *PasswordReset) userLogoutWebHook(ctx context.Context, ts *models.ChangePasswordTokenSource) {
	app, err := pr.Registry.ApplicationService().Get(bson.ObjectIdHex(ts.ClientID))
	if err != nil {
		log.Error(ctx, "Cannot execute user.logout WebHook, error on getting app by id", zap.Error(err))
		return
	}
	go func() {
		err := pr.WebHooks.UserLogout(ctx, ts.Subject, app.WebHooks)
		if err != nil {
			log.Error(ctx, "Error on user.logout WebHook", zap.Error(err))
		}
	}()
}
