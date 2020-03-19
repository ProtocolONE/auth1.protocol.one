package service

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/go-redis/redis"
)

const OneTimeTokenStoragePattern = "ott_data_%s"

// OneTimeTokenServiceInterface describes of methods for the one-time token service.
type OneTimeTokenServiceInterface interface {
	// Create creates a one-time token with arbitrary data and the specified settings
	// for the length of the token and its lifetime.
	Create(obj interface{}, settings *models.OneTimeTokenSettings) (*models.OneTimeToken, error)

	// Get returns the contents of a one-time token by its code.
	Get(token string, obj interface{}) error

	// Use returns the contents of a one-time token by its code and deletes it.
	Use(token string, obj interface{}) error
}

// OneTimeTokenService is the one-time token service.
type OneTimeTokenService struct {
	Redis    *redis.Client
	Settings *models.OneTimeTokenSettings
}

// NewOneTimeTokenService return new one-time token service.
func NewOneTimeTokenService(redis *redis.Client) *OneTimeTokenService {
	return &OneTimeTokenService{Redis: redis}
}

func (s *OneTimeTokenService) Create(obj interface{}, settings *models.OneTimeTokenSettings) (*models.OneTimeToken, error) {
	t := &models.OneTimeToken{
		Token: helper.GetRandString(settings.Length),
	}

	data, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	resSet := s.Redis.Set(fmt.Sprintf(OneTimeTokenStoragePattern, t.Token), data, 0)
	if resSet.Err() != nil {
		return nil, resSet.Err()
	}
	resExp := s.Redis.Expire(fmt.Sprintf(OneTimeTokenStoragePattern, t.Token), time.Duration(settings.TTL)*time.Second)
	return t, resExp.Err()
}

func (s *OneTimeTokenService) Get(token string, obj interface{}) error {
	res, err := s.Redis.Get(fmt.Sprintf(OneTimeTokenStoragePattern, token)).Bytes()
	if err != nil {
		return err
	}

	if err := json.Unmarshal(res, &obj); err != nil {
		return err
	}
	return nil
}

func (s *OneTimeTokenService) Use(token string, d interface{}) error {
	if err := s.Get(token, &d); err != nil {
		return err
	}

	return s.Redis.Del(fmt.Sprintf(OneTimeTokenStoragePattern, token)).Err()
}
