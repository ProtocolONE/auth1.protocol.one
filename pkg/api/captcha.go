package api

import (
	"context"
	"net/http"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/labstack/echo/v4"
)

func InitCaptcha(cfg *Server) error {
	c := &Captcha{
		recaptcha: cfg.Recaptcha,
		session:   service.NewSessionService(cfg.SessionConfig.Name),
	}
	cfg.Echo.Group("/captcha").
		POST("/re3", c.verify)

	return nil
}

var captchaKey = "captcha"

type Captcha struct {
	recaptcha *service.Recaptcha
	session   service.SessionService
}

func CaptchaCompleted(ctx echo.Context, s service.SessionService) (bool, error) {
	v, err := s.Get(ctx, captchaKey)
	if err != nil {
		return false, err
	}
	if v != nil {
		if done, ok := v.(bool); ok {
			return done, nil
		}
	}
	return false, nil
}

func (ctl *Captcha) verify(ctx echo.Context) error {
	var r struct {
		Token  string `json:"token"`
		Action string `json:"action"`
	}

	if err := ctx.Bind(&r); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
		}
		ctx.Error(err)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	result, err := ctl.recaptcha.Verify(context.TODO(), r.Token, r.Action, "") // TODO ip
	if err != nil {
		ctx.Error(err)
		return ctx.JSON(http.StatusInternalServerError, &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
		})
	}

	ctl.session.Set(ctx, captchaKey, result)

	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"success": result,
	})
}
