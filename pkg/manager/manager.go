package manager

import (
	"auth-one-api/pkg/database"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/go-redis/redis"
	"go.uber.org/zap"
)

type Config struct {
	Database   *database.Handler
	Redis      *redis.Client
	Logger     *zap.Logger
	MfaService proto.MfaService
}
