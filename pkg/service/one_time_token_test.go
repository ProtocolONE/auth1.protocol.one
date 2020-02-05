// +build integration

package service

import (
	"testing"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/go-redis/redis"
	"github.com/stretchr/testify/assert"
)

func TestOneTimeTokenSuccessCreate(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	defer client.Close()

	ott := NewOneTimeTokenService(client)
	token, err := ott.Create("test", &models.OneTimeTokenSettings{Length: 6, TTL: 3})
	assert.Nil(t, err)
	assert.Len(t, token.Token, 6)
}

func TestOneTimeTokenSuccessGetToken(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	defer client.Close()

	ott := NewOneTimeTokenService(client)
	expected := "test"
	token, err := ott.Create(expected, &models.OneTimeTokenSettings{Length: 6, TTL: 3})
	actual := ""
	err = ott.Get(token.Token, &actual)

	assert.Nil(t, err)
	assert.Equal(t, expected, actual)
}

func TestOneTimeTokenReturnErrorTokenNotFound(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	defer client.Close()

	ott := NewOneTimeTokenService(client)
	actual := ""
	err := ott.Get("notfound", &actual)

	assert.NotNil(t, err)
}

func TestOneTimeTokenSuccessUse(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	defer client.Close()

	ott := NewOneTimeTokenService(client)
	expected := "test"
	token, err := ott.Create(expected, &models.OneTimeTokenSettings{Length: 6, TTL: 3})
	actual := ""
	err = ott.Use(token.Token, &actual)

	assert.Nil(t, err)
	assert.Equal(t, expected, actual)
}

func TestOneTimeTokenAlreadyUse(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	defer client.Close()

	ott := NewOneTimeTokenService(client)
	expected := "test"
	token, err := ott.Create(expected, &models.OneTimeTokenSettings{Length: 6, TTL: 3})
	actual := ""
	ott.Use(token.Token, &actual)
	err = ott.Use(token.Token, &actual)

	assert.NotNil(t, err)
}
