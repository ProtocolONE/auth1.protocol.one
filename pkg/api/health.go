package api

import (
	"github.com/labstack/echo/v4"
	"net/http"
)

func InitHealth(cfg *Server) error {
	cfg.Echo.GET("/", index)
	cfg.Echo.GET("/health", health)

	return nil
}

func index(ctx echo.Context) error {
	return ctx.HTML(http.StatusOK, "<h1>Welcome to the Auth1!</h1>")
}

func health(ctx echo.Context) error {
	return ctx.HTML(http.StatusNoContent, "")
}
