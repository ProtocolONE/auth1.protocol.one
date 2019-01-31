package route

import (
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/manager"
	"github.com/labstack/echo"
	"net/http"
)

type UserInfo struct {
	Manager *manager.UserInfoManager
}

func InitUserInfo(cfg Config) error {
	route := &UserInfo{
		Manager: manager.NewUserInfoManager(cfg.Logger, cfg.Database),
	}

	cfg.Echo.GET("/userinfo", route.UserInfo)

	return nil
}

func (l *UserInfo) UserInfo(ctx echo.Context) error {
	token, e := l.Manager.UserInfo(ctx)
	if e != nil {
		return helper.NewErrorResponse(ctx, http.StatusForbidden, InvalidAuthTokenCode, e.GetMessage())
	}

	return ctx.JSON(http.StatusOK, token)
}
