package route

import (
	"auth-one-api/pkg/config"
	"auth-one-api/pkg/database"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/go-redis/redis"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra/sdk/go/hydra"
	"go.uber.org/zap"
)

type Config struct {
	Echo          *echo.Echo
	Logger        *zap.Logger
	Database      *database.Handler
	Redis         *redis.Client
	MfaService    proto.MfaService
	Hydra         *hydra.CodeGenSDK
	SessionConfig *config.SessionConfig
}
