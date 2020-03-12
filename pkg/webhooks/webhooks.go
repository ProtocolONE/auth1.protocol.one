package webhooks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/juju/zaputil/zapctx"
	"go.uber.org/zap"
)

const (
	UserLogoutAction = "user.logout"
)

type Hook struct {
	ID        string            `json:"id"`
	Action    string            `json:"action"`
	CreatedAt string            `json:"created_at"`
	Event     map[string]string `json:"event"`
}

type WebHooks struct{}

func NewWebhooks() *WebHooks {
	return &WebHooks{}
}

func (wh *WebHooks) UserLogout(ctx context.Context, userId string, endpoints []string) error {
	log := zapctx.Logger(ctx)

	uid, err := uuid.NewUUID()
	if err != nil {
		return err
	}

	hook := Hook{
		ID:        uid.String(),
		Action:    UserLogoutAction,
		CreatedAt: time.Now().Format(time.RFC3339),
		Event:     map[string]string{},
	}

	log.Info(fmt.Sprintf("Webhook %s started", hook.ID))
	trigger(ctx, endpoints, hook)
	log.Info(fmt.Sprintf("Webhook %s finished", hook.ID))

	return nil
}

func trigger(ctx context.Context, endpoints []string, hook Hook) {
	log := zapctx.Logger(ctx)

	jsonHook, err := json.Marshal(hook)
	if err != nil {
		log.Error(err.Error())
		return
	}

	buf := &bytes.Buffer{}
	buf.Write(jsonHook)

	log.Debug("webhook", zap.ByteString("body", jsonHook))

	wg := sync.WaitGroup{}
	wg.Add(len(endpoints))

	for _, url := range endpoints {
		go func() {
			defer wg.Done()
			err := post(url, buf)
			if err != nil {
				log.Error(err.Error(), zap.String("hook", hook.ID), zap.String("url", url))
			}
		}()
	}
	wg.Wait()
}

func post(url string, hook io.Reader) error {
	c := http.Client{
		Timeout: time.Second * 30,
	}

	resp, err := c.Post(url, "application/json", hook)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
