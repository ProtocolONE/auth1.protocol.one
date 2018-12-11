package api

import (
	"auth-one-api/pkg/config"
	"auth-one-api/pkg/models"
	"auth-one-api/pkg/route"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/sirupsen/logrus"
	"gopkg.in/go-playground/validator.v9"
	"reflect"
	"strconv"
	"strings"
)

type (
	ServerConfig struct {
		ServerConfig *config.ServerConfig
		Log          *logrus.Entry
		Jwt          *config.Jwt
	}

	Server struct {
		Log          *logrus.Entry
		Echo         *echo.Echo
		ServerConfig *config.ServerConfig
	}
)

func NewServer(config *ServerConfig) (*Server, error) {
	server := &Server{
		Log:          config.Log,
		Echo:         echo.New(),
		ServerConfig: config.ServerConfig,
	}

	server.Echo.Logger = Logger{config.Log.Logger}
	server.Echo.Use(LoggerHandler)

	server.Echo.Use(middleware.Logger())
	server.Echo.Use(middleware.Recover())
	server.Echo.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowHeaders: []string{"authorization", "content-type"},
	}))

	registerCustomValidator(server.Echo)

	if err := server.setupRoutes(); err != nil {
		server.Log.Fatal(err)
	}

	return server, nil
}

func registerCustomValidator(e *echo.Echo) {
	v := validator.New()
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]

		if name == "-" {
			return ""
		}

		return name
	})
	e.Validator = &models.CustomValidator{
		Validator: v,
	}
}

func (s *Server) Start() error {
	return s.Echo.Start(":" + strconv.Itoa(s.ServerConfig.Port))
}

func (s *Server) setupRoutes() error {
	routeConfig := route.Config{
		Echo:   s.Echo,
		Logger: s.Log,
	}

	if err := route.LogoutInit(routeConfig); err != nil {
		return err
	}
	if err := route.LoginInit(routeConfig); err != nil {
		return err
	}
	if err := route.SignUpInit(routeConfig); err != nil {
		return err
	}
	if err := route.PasswordLessInit(routeConfig); err != nil {
		return err
	}
	if err := route.ChangePasswordInit(routeConfig); err != nil {
		return err
	}
	if err := route.UserInfoInit(routeConfig); err != nil {
		return err
	}
	if err := route.MFAInit(routeConfig); err != nil {
		return err
	}
	if err := route.TokenInit(routeConfig); err != nil {
		return err
	}

	return nil
}
