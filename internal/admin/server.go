package admin

import (
	"context"
	"net/http/httputil"
	"net/url"

	"github.com/labstack/echo/v4"
	"go.uber.org/fx"
)

type Params struct {
	fx.In

	fx.Lifecycle
	Spaces    *SpaceHandler
	Providers *ProvidersHandler
}

type Server struct {
	engine *echo.Echo
}

func NewServer(p Params) *Server {
	ui, err := url.Parse("http://192.168.1.64:3000")
	if err != nil {
		panic(err)
	}

	var engine = echo.New()

	engine.GET("/api/spaces", p.Spaces.List)
	engine.GET("/api/spaces/:id", p.Spaces.Get)

	engine.GET("/api/identity_providers", p.Providers.List)
	engine.GET("/api/identity_providers/:id", p.Providers.Get)

	engine.GET("/*", echo.WrapHandler(httputil.NewSingleHostReverseProxy(ui)))

	s := &Server{
		engine: engine,
	}
	p.Lifecycle.Append(fx.Hook{
		OnStart: s.Start,
		OnStop:  s.Shutdown,
	})

	return s
}

func (s *Server) Start(ctx context.Context) error {
	go func() {
		s.engine.Start(":8080")
	}()
	return nil
}

func (s *Server) Serve(addr string) error {
	return s.engine.Start(addr)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.engine.Shutdown(ctx)
}
