package route

import (
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/manager"
	"auth-one-api/pkg/models"
	"fmt"
	"github.com/labstack/echo"
	"net/http"
)

type (
	Login struct {
		Manager manager.LoginManager
		Http    *echo.Echo
	}
)

func LoginInit(cfg Config) error {
	route := &Login{
		Manager: manager.InitLoginManager(cfg.Logger, cfg.Database, cfg.Redis),
		Http:    cfg.Echo,
	}

	cfg.Echo.GET("/authorize/link", route.AuthorizeLink)
	cfg.Echo.GET("/authorize/result", route.AuthorizeResult)
	cfg.Echo.GET("/authorize", route.Authorize)
	cfg.Echo.POST("/login", route.Login)

	return nil
}

func (l *Login) Authorize(ctx echo.Context) error {
	form := new(models.AuthorizeForm)

	if err := ctx.Bind(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	if err := l.Manager.Authorize(ctx, form); err != nil {
		return ctx.HTML(http.StatusBadRequest, err.GetMessage())
	}

	/*req, e := http.NewRequest("GET", form.RedirectUri, nil)
	if e != nil {
		return ctx.HTML(http.StatusBadRequest, e.GetMessage())
	}

	q := req.URL.Query()
	q.Add(`auth_one_ott`, ott.Token)
	req.URL.RawQuery = q.Encode()*/

	//return ctx.Redirect(http.StatusOK, req.URL.String())
	return nil
}

func (l *Login) AuthorizeResult(ctx echo.Context) error {
	form := new(models.AuthorizeResultForm)

	if err := ctx.Bind(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	t, err := l.Manager.AuthorizeResult(ctx, form)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, err.GetMessage())
	}

	if t != nil {
		return ctx.JSON(http.StatusOK, t)
	} else {
		return ctx.HTML(http.StatusOK, "")
	}
}

func (l *Login) AuthorizeLink(ctx echo.Context) error {
	form := new(models.AuthorizeLinkForm)

	if err := ctx.Bind(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	t, err := l.Manager.AuthorizeLink(ctx, form)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, err.GetMessage())
	}

	return ctx.JSON(http.StatusOK, t)
}

func (l *Login) Login(ctx echo.Context) (err error) {
	form := new(models.LoginForm)

	if err := ctx.Bind(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	token, e := l.Manager.Login(ctx, form)
	if e != nil {
		httpCode := http.StatusBadRequest
		code := BadRequiredCodeCommon
		message := fmt.Sprint(e)

		switch e.(type) {
		case *models.CaptchaRequiredError:
			httpCode = http.StatusPreconditionRequired
			code = CaptchaRequiredCode
		case *models.MFARequiredError:
			httpCode = http.StatusForbidden
			code = MFARequiredCode
		case *models.TemporaryLockedError:
			httpCode = http.StatusLocked
			code = TemporaryLockedCode
		case *models.CommonError:
			code = e.GetCode()
			message = e.GetMessage()
		default:
			code = UnknownErrorCode
			message = models.ErrorUnknownError
		}

		return helper.NewErrorResponse(ctx, httpCode, code, message)
	}

	return ctx.JSON(http.StatusOK, token)
}
