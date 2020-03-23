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

	"github.com/ProtocolONE/auth1.protocol.one/pkg/appcore/log"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	UserLogoutAction = "user.logout"
)

type Hook struct {
	ID        string            `json:"id"`
	Action    string            `json:"action"`
	UserID    string            `json:"user_id"`
	CreatedAt string            `json:"created_at"`
	Event     map[string]string `json:"event"`
}

type WebHooks struct{}

func NewWebhooks() *WebHooks {
	return &WebHooks{}
}

func (wh *WebHooks) UserLogout(ctx context.Context, userId string, endpoints []string) error {
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

	log.Info(ctx, fmt.Sprintf("Webhook %s started", hook.ID))
	trigger(ctx, endpoints, hook)
	log.Info(ctx, fmt.Sprintf("Webhook %s finished", hook.ID))

	return nil
}

func trigger(ctx context.Context, endpoints []string, hook Hook) {
	jsonHook, err := json.Marshal(hook)
	if err != nil {
		log.Error(ctx, err.Error())
		return
	}

	buf := &bytes.Buffer{}
	buf.Write(jsonHook)

	log.Debug(ctx, "webhook", zap.ByteString("body", jsonHook))

	wg := sync.WaitGroup{}
	wg.Add(len(endpoints))

	// todo: do queue and retry on failure
	for _, url := range endpoints {
		go func() {
			defer wg.Done()
			err := post(url, buf)
			if err != nil {
				log.Error(ctx, err.Error(), zap.String("hook", hook.ID), zap.String("url", url))
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
