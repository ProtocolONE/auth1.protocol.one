package route

import (
	"auth-one-api/pkg/api/manager"
	"auth-one-api/pkg/api/models"
	"auth-one-api/pkg/helper"
	"fmt"
	"github.com/labstack/echo"
	"net/http"
)

type SignUp struct {
	Manager manager.SignUpManager
}

func SignUpInit(cfg Config) error {
	route := &SignUp{
		Manager: manager.InitSignUpManager(cfg.Logger),
	}

	cfg.Http.GET("/logout", route.SignUp)

	return nil
}

func (l *SignUp) SignUp(ctx echo.Context) error {
	form := new(models.SignUpForm)

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

	token, e := l.Manager.SignUp(form)
	if e != nil {
		return helper.NewErrorResponse(ctx, BadRequiredHttpCode, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}
