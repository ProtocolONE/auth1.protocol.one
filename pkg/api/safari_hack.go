package api

import (
	"github.com/labstack/echo/v4"
	"net/http"
)

func InitSafariHack(cfg *Server) error {
	cfg.Echo.GET("/safari_hack", SafariHack)

	return nil
}

func SafariHack(ctx echo.Context) error {
	return ctx.HTML(http.StatusOK, "<script>window.location.replace(document.referrer)</script>")
}
