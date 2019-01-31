package api

import (
	"auth-one-api/pkg/config"
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"auth-one-api/pkg/route"
	"github.com/ProtocolONE/mfa-service/pkg"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/go-redis/redis"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/micro/go-micro"
	k8s "github.com/micro/kubernetes/go/micro"
	"go.uber.org/zap"
	"gopkg.in/go-playground/validator.v9"
	"html/template"
	"io"
	"reflect"
	"strconv"
	"strings"
)

type ServerConfig struct {
	ApiConfig      *config.ApiConfig
	Logger         *zap.Logger
	JwtConfig      *config.JwtConfig
	DatabaseConfig *config.DatabaseConfig
	RedisConfig    *config.RedisConfig
	Kubernetes     *config.KubernetesConfig
}

type Server struct {
	Log          *zap.Logger
	Echo         *echo.Echo
	ServerConfig *config.ApiConfig
	DbHandler    *database.Handler
	RedisHandler *redis.Client
	MfaService   proto.MfaService
}

type Template struct {
	templates *template.Template
}

func NewServer(c *ServerConfig) (*Server, error) {
	db, err := database.NewConnection(c.DatabaseConfig)
	if err != nil {
		c.Logger.Fatal("Database connection failed with error", zap.Error(err))
	}

	r := redis.NewClient(&redis.Options{
		Addr:     c.RedisConfig.Addr,
		Password: c.RedisConfig.Password,
	})

	var service micro.Service
	if c.Kubernetes.Service.Host == "" {
		service = micro.NewService()
		c.Logger.Info("Initialize micro service")
	} else {
		service = k8s.NewService()
		c.Logger.Info("Initialize k8s service")
	}
	service.Init()
	ms := proto.NewMfaService(mfa.ServiceName, service.Client())

	server := &Server{
		Log:          c.Logger,
		Echo:         echo.New(),
		DbHandler:    &database.Handler{Name: c.DatabaseConfig.Database, Session: db},
		RedisHandler: r,
		MfaService:   ms,
		ServerConfig: c.ApiConfig,
	}

	t := &Template{
		templates: template.Must(template.ParseGlob("public/templates/*.html")),
	}
	server.Echo.Renderer = t
	server.Echo.Use(ZapLogger(c.Logger))
	server.Echo.Use(middleware.Recover())
	server.Echo.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowHeaders: []string{"authorization", "content-type"},
	}))

	registerCustomValidator(server.Echo)

	if err := server.setupRoutes(); err != nil {
		server.Log.Fatal("Setup routes failed", zap.Error(err))
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
		Echo:       s.Echo,
		Logger:     s.Log,
		Database:   s.DbHandler,
		Redis:      s.RedisHandler,
		MfaService: s.MfaService,
	}

	if err := route.InitLogout(routeConfig); err != nil {
		return err
	}
	if err := route.InitLogin(routeConfig); err != nil {
		return err
	}
	if err := route.InitSignUp(routeConfig); err != nil {
		return err
	}
	if err := route.InitPasswordLess(routeConfig); err != nil {
		return err
	}
	if err := route.InitChangePassword(routeConfig); err != nil {
		return err
	}
	if err := route.InitUserInfo(routeConfig); err != nil {
		return err
	}
	if err := route.InitMFA(routeConfig); err != nil {
		return err
	}
	if err := route.InitToken(routeConfig); err != nil {
		return err
	}
	if err := route.InitManage(routeConfig); err != nil {
		return err
	}

	return nil
}

func (t *Template) Render(w io.Writer, name string, data interface{}, ctx echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}
