package route

import (
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/manager"
	"fmt"
	"github.com/labstack/echo"
	"net/http"
)

type UserInfo struct {
	Manager manager.UserInfoManager
}

func UserInfoInit(cfg Config) error {
	route := &UserInfo{
		Manager: manager.InitUserInfoManager(cfg.Logger),
	}

	cfg.Echo.GET("/userinfo", route.UserInfo)

	return nil
}

func (l *UserInfo) UserInfo(ctx echo.Context) error {
	authHeader := ctx.Request().Header.Get(`Authorization`)
	tokenSource, err := helper.GetTokenFromAuthHeader(authHeader)
	if err != nil {
		return helper.NewErrorResponse(
			ctx,
			http.StatusBadRequest,
			`auth_header_invalid`,
			fmt.Sprint(err),
		)
	}

	token, e := l.Manager.UserInfo(tokenSource)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusForbidden, InvalidAuthTokenCode, e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}
