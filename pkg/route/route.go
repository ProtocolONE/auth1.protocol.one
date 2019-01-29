package route

import (
	"auth-one-api/pkg/database"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/go-redis/redis"
	"github.com/labstack/echo"
	"go.uber.org/zap"
)

type Config struct {
	Echo       *echo.Echo
	Logger     *zap.Logger
	Database   *database.Handler
	Redis      *redis.Client
	MfaService proto.MfaService
}
