package api

import (
	"context"
	"net/http"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/api/apierror"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

func InitCaptcha(cfg *Server) error {
	c := &Captcha{
		recaptcha: cfg.Recaptcha,
		session:   service.NewSessionService(cfg.SessionConfig.Name),
	}
	cfg.Echo.Group("/api/captcha").
		POST("/re3", c.verify)

	return nil
}

var captchaKey = "captcha"

type Captcha struct {
	recaptcha *service.Recaptcha
	session   service.SessionService
}

func (ctl *Captcha) verify(ctx echo.Context) error {
	var r struct {
		Token  string `json:"token"`
		Action string `json:"action"`
	}

	if err := ctx.Bind(&r); err != nil {
		return apierror.InvalidRequest(err)
	}

	result, err := ctl.recaptcha.Verify(context.TODO(), r.Token, r.Action, "") // TODO ip
	if err != nil {
		return errors.Wrap(err, "unable to verify captcha")
	}

	ctl.session.Set(ctx, captchaKey, result)

	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"success": result,
	})
}
