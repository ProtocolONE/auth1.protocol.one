package api

import (
	"auth-one-api/pkg/config"
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"auth-one-api/pkg/route"
	"github.com/ProtocolONE/mfa-service/pkg"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/boj/redistore"
	"github.com/globalsign/mgo"
	"github.com/go-redis/redis"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/micro/go-micro"
	k8s "github.com/micro/kubernetes/go/micro"
	"github.com/ory/hydra/sdk/go/hydra"
	"go.uber.org/zap"
	"gopkg.in/go-playground/validator.v9"
	"html/template"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
)

type ServerConfig struct {
	ApiConfig      *config.ApiConfig
	JwtConfig      *config.JwtConfig
	DatabaseConfig *config.DatabaseConfig
	Kubernetes     *config.KubernetesConfig
	HydraConfig    *config.HydraConfig
	SessionConfig  *config.SessionConfig
	MongoDB        *mgo.Session
	SessionStore   *redistore.RediStore
	RedisClient    *redis.Client
}

type Server struct {
	Echo          *echo.Echo
	ServerConfig  *config.ApiConfig
	RedisHandler  *redis.Client
	MfaService    proto.MfaService
	Hydra         *hydra.CodeGenSDK
	SessionConfig *config.SessionConfig
}

type Template struct {
	templates *template.Template
}

func NewServer(c *ServerConfig) (*Server, error) {
	var service micro.Service
	if c.Kubernetes.Service.Host == "" {
		service = micro.NewService()
		zap.L().Info("Initialize micro service")
	} else {
		service = k8s.NewService()
		zap.L().Info("Initialize k8s service")
	}
	service.Init()
	ms := proto.NewMfaService(mfa.ServiceName, service.Client())

	h, err := hydra.NewSDK(&hydra.Configuration{
		AdminURL: c.HydraConfig.AdminURL,
	})
	if err != nil {
		zap.L().Fatal("Hydra SDK creation failed", zap.Error(err))
	}

	server := &Server{
		Echo:          echo.New(),
		RedisHandler:  c.RedisClient,
		MfaService:    ms,
		ServerConfig:  c.ApiConfig,
		Hydra:         h,
		SessionConfig: c.SessionConfig,
	}

	t := &Template{
		templates: template.Must(template.ParseGlob("public/templates/*.html")),
	}
	server.Echo.Renderer = t
	server.Echo.Use(ZapLogger(zap.L()))
	server.Echo.Use(middleware.Recover())
	// TODO: Validate origins for each application by settings
	server.Echo.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowHeaders:     []string{"authorization", "content-type"},
		AllowOrigins:     c.ApiConfig.AllowOrigins,
		AllowCredentials: c.ApiConfig.AllowCredentials,
		AllowMethods:     []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete, http.MethodOptions},
	}))
	server.Echo.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup: "header:X-XSRF-TOKEN",
		CookieName:  "_csrf",
		Skipper:     csrfSkipper,
	}))
	server.Echo.Use(session.Middleware(c.SessionStore))
	server.Echo.Use(middleware.RequestID())
	server.Echo.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			s := c.MongoDB.Copy()
			defer s.Close()

			ctx.Set("database", s)
			return next(ctx)
		}
	})

	registerCustomValidator(server.Echo)

	if err := server.setupRoutes(); err != nil {
		zap.L().Fatal("Setup routes failed", zap.Error(err))
	}

	return server, nil
}

func createMongoIndex(db *mgo.Session) {
	err := db.DB("").C(database.TableUser).EnsureIndex(mgo.Index{
		Key:        []string{"app_id", "email"},
		Unique:     true,
		DropDups:   true,
		Background: true,
		Sparse:     false,
	})

	if err != nil {
		zap.L().Fatal("Ensure user collection index failed", zap.Error(err))
	}

	err = db.DB("").C(database.TableUserIdentity).EnsureIndex(mgo.Index{
		Key:        []string{"app_id", "external_id", "connection"},
		Unique:     true,
		DropDups:   true,
		Background: true,
		Sparse:     false,
	})

	if err != nil {
		zap.L().Fatal("Ensure user collection index failed", zap.Error(err))
	}
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
		Echo:          s.Echo,
		Redis:         s.RedisHandler,
		MfaService:    s.MfaService,
		Hydra:         s.Hydra,
		SessionConfig: s.SessionConfig,
	}

	if err := route.InitLogin(routeConfig); err != nil {
		return err
	}

	if err := route.InitPasswordLess(routeConfig); err != nil {
		return err
	}

	if err := route.InitChangePassword(routeConfig); err != nil {
		return err
	}

	if err := route.InitMFA(routeConfig); err != nil {
		return err
	}

	if err := route.InitManage(routeConfig); err != nil {
		return err
	}

	if err := route.InitOauth2(routeConfig); err != nil {
		return err
	}

	return nil
}

func (t *Template) Render(w io.Writer, name string, data interface{}, ctx echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func csrfSkipper(ctx echo.Context) bool {
	return ctx.Path() != "/oauth2/login" && ctx.Path() != "/oauth2/signup"
}
