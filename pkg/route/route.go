package route

import (
	"auth-one-api/pkg/database"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/go-redis/redis"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/ory/hydra/sdk/go/hydra"
	"go.uber.org/zap"
)

type Config struct {
	Echo       *echo.Echo
	Logger     *zap.Logger
	Database   *database.Handler
	Redis      *redis.Client
	MfaService proto.MfaService
	Hydra      *hydra.CodeGenSDK
	Session    *sessions.Session
}
