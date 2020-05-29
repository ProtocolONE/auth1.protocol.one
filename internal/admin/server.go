package admin

import (
	"context"
	"net/http/httputil"
	"net/url"

	"github.com/labstack/echo/v4"
)

type Server struct {
	engine *echo.Echo
}

func NewServer() *Server {
	engine := echo.New()

	ui, err := url.Parse("http://localhost:3000")
	if err != nil {
		panic(err)
	}

	engine.GET("/api/spaces")
	engine.GET("/*", echo.WrapHandler(httputil.NewSingleHostReverseProxy(ui)))

	return &Server{
		engine: engine,
	}
}

func (s *Server) Serve(addr string) error {
	return s.engine.Start(addr)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.engine.Shutdown(ctx)
}
