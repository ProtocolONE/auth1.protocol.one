package service

import (
	"encoding/json"
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/go-redis/redis"
	"time"
)

const OneTimeTokenStoragePattern = "ott_data_%s"

type OneTimeTokenServiceInterface interface {
	Create(interface{}, *models.OneTimeTokenSettings) (*models.OneTimeToken, error)
	Get(string, interface{}) error
	Use(string, interface{}) error
}

type OneTimeTokenService struct {
	Redis    *redis.Client
	Settings *models.OneTimeTokenSettings
}

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
