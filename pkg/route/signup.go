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

type SignUp struct {
	Manager *manager.SignUpManager
	logger  *zap.Logger
}

func InitSignUp(cfg Config) error {
	route := &SignUp{
		Manager: manager.InitSignUpManager(cfg.Logger, cfg.Database),
		logger:  cfg.Logger,
	}

	cfg.Echo.POST("/signup", route.SignUp)

	return nil
}

func (l *SignUp) SignUp(ctx echo.Context) error {
	form := new(models.SignUpForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("SignUp bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
			"SignUp validate form failed",
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	token, e := l.Manager.SignUp(ctx, form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}
