package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/centrifugal/gocent"
)

type CentrifugoServiceInterface interface {
	InProgress(loginChallenge string) error
	Success(loginChallenge, url string) error
}

type Centrifugo struct {
	config *config.Centrifugo
	client *gocent.Client
}

func NewCentrifugoService(cfg *config.Centrifugo) *Centrifugo {
	c := gocent.New(gocent.Config{
		Addr: cfg.Addr,
		Key:  cfg.ApiKey,
	})

	return &Centrifugo{
		client: c,
		config: cfg,
	}
}

func (c *Centrifugo) InProgress(loginChallenge string) error {
	ctx := context.Background()
	data, _ := json.Marshal(map[string]string{
		"status": "in_progress",
	})
	return c.client.Publish(ctx, fmt.Sprintf("%s#%s", c.config.LauncherChannel, loginChallenge), data)
}

func (c *Centrifugo) Success(loginChallenge, url string) error {
	ctx := context.Background()
	data, _ := json.Marshal(map[string]string{
		"status": "success",
		"url":    url,
	})

	return c.client.Publish(ctx, fmt.Sprintf("%s#%s", c.config.LauncherChannel, loginChallenge), data)
}
