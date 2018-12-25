package api

import (
	"auth-one-api/pkg/config"
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"auth-one-api/pkg/route"
	"github.com/go-redis/redis"
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
		ApiConfig      *config.ApiConfig
		Logger         *logrus.Entry
		JwtConfig      *config.JwtConfig
		DatabaseConfig *config.DatabaseConfig
		RedisConfig    *config.RedisConfig
	}

	Server struct {
		Log          *logrus.Entry
		Echo         *echo.Echo
		ServerConfig *config.ApiConfig
		DbHandler    *database.Handler
		RedisHandler *redis.Client
	}
)

func NewServer(config *ServerConfig) (*Server, error) {
	db, err := database.NewConnection(config.DatabaseConfig)
	if err != nil {
		config.Logger.Fatalf("Database connection failed with error: %s\n", err)
	}

	client := redis.NewClient(&redis.Options{
		Addr:     config.RedisConfig.Addr,
		Password: config.RedisConfig.Password,
	})

	server := &Server{
		Log:          config.Logger,
		Echo:         echo.New(),
		DbHandler:    &database.Handler{Name: config.DatabaseConfig.Database, Session: db},
		RedisHandler: client,
		ServerConfig: config.ApiConfig,
	}

	server.Echo.Logger = Logger{config.Logger.Logger}
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
		Echo:     s.Echo,
		Logger:   s.Log,
		Database: s.DbHandler,
		Redis:    s.RedisHandler,
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
	if err := route.ManageInit(routeConfig); err != nil {
		return err
	}

	return nil
}
