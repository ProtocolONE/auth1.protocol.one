package route

import (
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/manager"
	"auth-one-api/pkg/models"
	"fmt"
	"github.com/labstack/echo"
	"go.uber.org/zap"
	"net/http"
)

type (
	Login struct {
		Manager *manager.LoginManager
		Http    *echo.Echo
		logger  *zap.Logger
	}
)

func InitLogin(cfg Config) error {
	route := &Login{
		Manager: manager.NewLoginManager(cfg.Logger, cfg.Database, cfg.Redis),
		Http:    cfg.Echo,
		logger:  cfg.Logger,
	}

	cfg.Echo.GET("/authorize/link", route.AuthorizeLink)
	cfg.Echo.GET("/authorize/result", route.AuthorizeResult)
	cfg.Echo.GET("/authorize", route.Authorize)
	cfg.Echo.GET("/login/form", route.LoginPage)
	cfg.Echo.GET("/login/ott", route.LoginByOTT)
	cfg.Echo.POST("/login", route.Login)

	return nil
}

func (l *Login) Authorize(ctx echo.Context) error {
	form := new(models.AuthorizeForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("Authorize bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
			"Authorize validate form failed",
			zap.Object("AuthorizeForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	str, err := l.Manager.Authorize(ctx, form)
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, err.GetMessage())
	}

	return ctx.Redirect(http.StatusOK, str)
}

func (l *Login) AuthorizeResult(ctx echo.Context) error {
	form := new(models.AuthorizeResultForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("AuthorizeResult bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
			"AuthorizeResult validate form failed",
			zap.Object("AuthorizeResultForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	t, err := l.Manager.AuthorizeResult(ctx, form)
	// WTF result HTML/JSON???

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
		l.logger.Error("AuthorizeLink bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
			"AuthorizeLink validate form failed",
			zap.Object("AuthorizeLinkForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	t, err := l.Manager.AuthorizeLink(ctx, form)

	// WTF result HTML/JSON???
	if err != nil {
		return ctx.HTML(http.StatusBadRequest, err.GetMessage())
	}

	return ctx.JSON(http.StatusOK, t)
}

func (l *Login) Login(ctx echo.Context) (err error) {
	form := new(models.LoginForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("Login bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
			"Login validate form failed",
			zap.Object("LoginForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	res, e := l.Manager.Login(ctx, form)
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

	return ctx.JSON(http.StatusOK, res)
}

func (l *Login) LoginPage(ctx echo.Context) (err error) {
	form := new(models.LoginPageForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("Login page bind form failed", zap.Error(err))
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	return ctx.Render(http.StatusOK, "login_form.html", map[string]interface{}{
		"ClientID":    form.ClientID,
		"RedirectUri": form.RedirectUri,
	})
}

func (l *Login) LoginByOTT(ctx echo.Context) error {
	form := new(models.OneTimeTokenForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("TokenOTT bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
			"TokenOTT bind validate failed",
			zap.Object("OneTimeTokenForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	token, e := l.Manager.LoginByOTT(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}
