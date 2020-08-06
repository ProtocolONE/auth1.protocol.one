package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	engine.HideBanner = true
	engine.Debug = true

	engine.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		ExposeHeaders: []string{"X-Total-Count"},
		AllowHeaders:  []string{"Content-Type", "Authorization"},
		AllowOrigins:  []string{"http://localhost:3000", "http://localhost:6001"},
		AllowMethods:  []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete, http.MethodOptions},
	}))

	engine.Use(middleware.BasicAuthWithConfig(middleware.BasicAuthConfig{
		Realm: "Auth1",
		Validator: func(login, password string, ctx echo.Context) (bool, error) {
			if login != "admin" {
				return false, nil
			}

			hash := sha256.Sum256([]byte(password + "&()123#^^"))
			if hex.EncodeToString(hash[:]) != "ef778317fa2c077d63c8d49cb3adaffa3279d2976c3ce22ee3ca65aeb849fd61" {
				return false, nil
			}
			return true, nil
		},
	}))

	engine.GET("/api/spaces", p.Spaces.List)
	engine.POST("/api/spaces", p.Spaces.Create)
	engine.GET("/api/spaces/:id", p.Spaces.Get)
	engine.PUT("/api/spaces/:id", p.Spaces.Update)

	engine.GET("/api/identity_providers", p.Providers.List)
	engine.POST("/api/identity_providers", p.Providers.Create)
	engine.GET("/api/identity_providers/:id", p.Providers.Get)
	engine.PUT("/api/identity_providers/:id", p.Providers.Update)
	engine.DELETE("/api/identity_providers/:id", p.Providers.Delete)

	engine.GET("/api/users", p.Users.List)
	engine.GET("/api/users/:id", p.Users.Get)
	engine.PUT("/api/users/:id", p.Users.Update)

	engine.GET("/api/apps", p.Apps.List)
	engine.GET("/api/apps/:id", p.Apps.Get)

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
		s.engine.Start(":8081")
	}()
	return nil
}

func (s *Server) Serve(addr string) error {
	return s.engine.Start(addr)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.engine.Shutdown(ctx)
}
