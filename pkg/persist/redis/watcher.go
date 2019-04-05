package rediswatcher

import (
	"encoding/json"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/persist"
	"github.com/go-redis/redis"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type Watcher struct {
	id       uuid.UUID
	options  WatcherOptions
	conn     *redis.Client
	callback map[string]func(string)
	channels chan string
	quit     chan bool
}

type event struct {
	Id      uuid.UUID
	Payload string
}

func NewWatcher(client *redis.Client, setters ...WatcherOption) persist.Watcher {
	id, err := uuid.NewRandom()
	if err != nil {
		panic(err)
	}

	w := &Watcher{
		quit:     make(chan bool),
		channels: make(chan string),
		callback: make(map[string]func(string)),
		id:       id,
	}

	for _, setter := range setters {
		setter(&w.options)
	}

	w.conn = client
	go func() {
		err := w.subscribe()
		if err != nil {
			panic(err)
		}
	}()

	return w
}

func (w *Watcher) Close() error {
	w.quit <- true
	return nil
}

// SetUpdateCallBack sets the update callback function invoked by the watcher
// when the data is updated.
func (w *Watcher) SetUpdateCallback(channel string, callback func(string)) {
	w.callback[channel] = callback
	w.channels <- channel
}

// Update publishes a message to all other instances telling them to
// invoke their update callback
func (w *Watcher) Update(channel string, identity string) error {
	ev, err := json.Marshal(&event{
		Id:      w.id,
		Payload: identity,
	})

	if err != nil {
		return err
	}

	return w.conn.Publish(channel, ev).Err()
}

func (w *Watcher) subscribe() error {
	ps := w.conn.Subscribe()
	defer func() {
		err := ps.Close()
		if err != nil {
			zap.L().Error("Failed to close watcher subscription", zap.Error(err))
		}
	}()

	ch := ps.Channel()

	for {
		select {
		case channel := <-w.channels:
			err := ps.Subscribe(channel)
			if err != nil {
				zap.L().Error("Failed to subscribe channel", zap.String("channel", channel))
			}
		case msg := <-ch:
			if len(w.callback) == 0 {
				continue
			}

			ev := event{}
			err := json.Unmarshal([]byte(msg.Payload), &ev)
			if err != nil {
				zap.L().Error(
					"Failed to unmarshal channel payload",
					zap.String("channel", msg.Channel),
					zap.String("payload", msg.Payload))
				continue
			}

			if w.options.RaiseOwn == false && w.id == ev.Id {
				continue
			}

			if h, ok := w.callback[msg.Channel]; ok {
				h(ev.Payload)
			}
		case <-w.quit:
			return nil
		}
	}
}
