package route

import (
	"auth-one-api/pkg/api/manager"
	"auth-one-api/pkg/helper"
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

	cfg.Http.GET("/userinfo", route.UserInfo)

	return nil
}

func (l *UserInfo) UserInfo(ctx echo.Context) error {
	token, e := l.Manager.UserInfo()
	if e != nil {
		return helper.NewErrorResponse(ctx, BadRequiredHttpCode, e.GetCode(), e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}
