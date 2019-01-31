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

type Token struct {
	Manager *manager.TokenManager
	logger  *zap.Logger
}

func InitToken(cfg Config) error {
	route := &Token{
		Manager: manager.NewTokenManager(cfg.Logger),
		logger:  cfg.Logger,
	}

	cfg.Echo.GET("/token/refresh", route.TokenRefresh)

	return nil
}

func (l *Token) TokenRefresh(ctx echo.Context) error {
	form := new(models.RefreshTokenForm)

	if err := ctx.Bind(form); err != nil {
		l.logger.Error("TokenRefresh bind form failed", zap.Error(err))

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			BadRequiredCodeCommon,
			models.ErrorInvalidRequestParameters,
		)
	}

	if err := ctx.Validate(form); err != nil {
		l.logger.Error(
			"TokenRefresh validate form failed",
			zap.Object("RefreshTokenForm", form),
			zap.Error(err),
		)

		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			models.ErrorRequiredField,
		)
	}

	token, e := l.Manager.Refresh(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusBadRequest, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}
