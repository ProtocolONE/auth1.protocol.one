package manager

import (
	"auth-one-api/pkg/database"
	"github.com/go-redis/redis"
	"github.com/sirupsen/logrus"
)

type Config struct {
	Database *database.Handler
	Redis    *redis.Client
	Logger   *logrus.Entry
}
