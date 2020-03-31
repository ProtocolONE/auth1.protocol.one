package service

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/api/apierror"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/go-redis/redis"
)

const LauncherTokenStoragePattern = "lts_data_%s"

// LauncherTokenServiceInterface describes of methods for the launcher token service.
type LauncherTokenServiceInterface interface {
	// Set creates a launcher token with arbitrary data and the specified settings
	Set(key string, obj interface{}, settings *models.LauncherTokenSettings) error

	// Get returns the contents of a launcher token by its code.
	Get(key string, obj interface{}) error

	// Use returns the contents of a launcher token by its code and deletes it.
	Use(key string, obj interface{}) error
}

// LauncherTokenService is the launcher token service.
type LauncherTokenService struct {
	Redis    *redis.Client
	Settings *models.LauncherTokenSettings
}

// LauncherTimeTokenService return new one-time token service.
func NewLauncherTokenService(redis *redis.Client) LauncherTokenServiceInterface {
	return &LauncherTokenService{
		Redis: redis,
	}
}

func (s *LauncherTokenService) Set(key string, obj interface{}, settings *models.LauncherTokenSettings) error {
	key = fmt.Sprintf(LauncherTokenStoragePattern, key)

	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	resSet := s.Redis.Set(key, data, 0)
	if resSet.Err() != nil {
		return resSet.Err()
	}
	resExp := s.Redis.Expire(key, time.Duration(settings.TTL)*time.Second)
	return resExp.Err()
}

func (s *LauncherTokenService) Get(key string, obj interface{}) error {
	res, err := s.Redis.Get(fmt.Sprintf(LauncherTokenStoragePattern, key)).Bytes()
	if err != nil {
		if err == redis.Nil {
			return apierror.NotFound
		}
		return err
	}

	if err := json.Unmarshal(res, &obj); err != nil {
		return err
	}
	return nil
}

func (s *LauncherTokenService) Use(key string, d interface{}) error {
	if err := s.Get(key, &d); err != nil {
		return err
	}

	return s.Redis.Del(fmt.Sprintf(LauncherTokenStoragePattern, key)).Err()
}
