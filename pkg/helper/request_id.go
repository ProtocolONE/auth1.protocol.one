package helper

import "github.com/labstack/echo/v4"

func GetRequestIdFromHeader(ctx echo.Context) string {
	return ctx.Response().Header().Get(echo.HeaderXRequestID)
}
