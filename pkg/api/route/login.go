package route

import (
	"auth-one-api/pkg/api/manager"
	"auth-one-api/pkg/api/models"
	"auth-one-api/pkg/helper"
	"fmt"
	"github.com/labstack/echo"
	"net/http"
)

const (
	BadRequiredHttpCode     = 400
	BadRequiredCodeCommon   = `invalid_argument`
	BadRequiredCodeField    = `field:%s`
	MFARequiredHttpCode     = 403
	MFARequiredCode         = `mfa_required`
	CaptchaRequiredCode     = 428
	CaptchaRequiredMessage  = `captcha_required`
	TemporaryLockedHttpCode = 423
	TemporaryLockedCode     = `login_temporary_locked`
)

type (
	Login struct {
		Manager manager.LoginManager
		Http    *echo.Echo
	}
)

func LoginInit(cfg Config) error {
	route := &Login{
		Manager: manager.InitLoginManager(cfg.Logger),
		Http:    cfg.Http,
	}

	cfg.Http.GET("/authorize/result", route.AuthorizeResult)
	cfg.Http.GET("/authorize", route.Authorize)
	cfg.Http.POST("/login", route.Login)

	return nil
}

func (l *Login) Authorize(ctx echo.Context) error {
	form := new(models.AuthorizeForm)

	if err := ctx.Bind(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			BadRequiredHttpCode,
			BadRequiredCodeCommon,
			`Invalid request parameters`,
		)
	}

	if err := ctx.Validate(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			BadRequiredHttpCode,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			`This is required field`,
		)
	}

	ott, err := l.Manager.Authorize(form)
	if err != nil {
		return ctx.HTML(BadRequiredHttpCode, err.GetMessage())
	}

	req, e := http.NewRequest("GET", form.RedirectUri, nil)
	if e != nil {
		return ctx.HTML(BadRequiredHttpCode, err.GetMessage())
	}

	q := req.URL.Query()
	q.Add(`auth_one_ott`, ott.Token)
	req.URL.RawQuery = q.Encode()

	return ctx.Redirect(http.StatusOK, req.URL.String())
}

func (l *Login) AuthorizeResult(ctx echo.Context) error {
	form := new(models.AuthorizeResultForm)

	if err := ctx.Bind(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			BadRequiredHttpCode,
			BadRequiredCodeCommon,
			`Invalid request parameters`,
		)
	}

	if err := ctx.Validate(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			BadRequiredHttpCode,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			`This is required field`,
		)
	}

	err := l.Manager.AuthorizeResult(form)
	if err != nil {
		return ctx.HTML(BadRequiredHttpCode, err.GetMessage())
	}

	return ctx.HTML(http.StatusOK, form.WsUrl)
}

func (l *Login) Login(ctx echo.Context) (err error) {
	form := new(models.LoginForm)

	if err := ctx.Bind(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			BadRequiredHttpCode,
			BadRequiredCodeCommon,
			`Invalid request parameters`,
		)
	}

	if err := ctx.Validate(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			BadRequiredHttpCode,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			`This is required field`,
		)
	}

	token, e := l.Manager.Login(form)
	if e != nil {
		httpCode := BadRequiredHttpCode
		code := BadRequiredCodeCommon
		message := fmt.Sprint(e)

		switch e.(type) {
		case *models.CaptchaRequiredError:
			httpCode = CaptchaRequiredCode
			code = CaptchaRequiredMessage
		case *models.MFARequiredError:
			httpCode = MFARequiredHttpCode
			code = MFARequiredCode
		case *models.TemporaryLockedError:
			httpCode = TemporaryLockedHttpCode
			code = TemporaryLockedCode
		case *models.CommonError:
			code = e.GetCode()
			message = e.GetMessage()
		default:
			code = `unknown_error`
			message = `Unknown error`
		}

		return helper.NewErrorResponse(ctx, httpCode, code, message)
	}

	return ctx.JSON(http.StatusOK, token)
}
