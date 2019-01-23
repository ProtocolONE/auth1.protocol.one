package route

import (
	"auth-one-api/pkg/database"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/go-redis/redis"
	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
)

type Config struct {
	Echo       *echo.Echo
	Logger     *logrus.Entry
	Database   *database.Handler
	Redis      *redis.Client
	MfaService proto.MfaService
}
