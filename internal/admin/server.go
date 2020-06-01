package admin

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/fx"
)

type Params struct {
	fx.In

	fx.Lifecycle
	Spaces    *SpaceHandler
	Providers *ProvidersHandler
	Users     *UsersHandler
	Apps      *ApplicationsHandler
}

type Server struct {
	engine *echo.Echo
}

func NewServer(p Params) *Server {
	var engine = echo.New()

	engine.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		ExposeHeaders: []string{"X-Total-Count"},
		AllowHeaders:  []string{"Content-Type"},
		AllowOrigins:  []string{"http://localhost:3000", "http://localhost:6001"},
		AllowMethods:  []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete, http.MethodOptions},
	}))

	engine.GET("/api/spaces", p.Spaces.List)
	engine.GET("/api/spaces/:id", p.Spaces.Get)
	engine.POST("/api/spaces", p.Spaces.Create)

	engine.GET("/api/identity_providers", p.Providers.List)
	engine.GET("/api/identity_providers/:id", p.Providers.Get)

	engine.GET("/api/users", p.Users.List)
	engine.GET("/api/users/:id", p.Users.Get)

	engine.GET("/api/apps", p.Apps.List)
	engine.GET("/api/apps/:id", p.Apps.Get)

	// ui, err := url.Parse("http://192.168.1.64:3000")
	// if err != nil {
	// 	panic(err)
	// }
	// engine.GET("/*", echo.WrapHandler(httputil.NewSingleHostReverseProxy(ui)))
	engine.Static("/", "admin/build")

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
