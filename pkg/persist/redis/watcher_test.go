// +build integration

package rediswatcher

import (
	"sync"
	"testing"
	"time"

	"github.com/go-redis/redis"
	"github.com/stretchr/testify/assert"
)

func TestSubscribe(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	defer client.Close()

	w := NewWatcher(client, RaiseOwn(true))
	defer w.Close()

	ch := make(chan string)
	w.SetUpdateCallback("test", func(msg string) {
		ch <- msg
	})

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		select {
		case res := <-ch:
			assert.Equal(t, "data", res)
			wg.Done()
		case <-time.After(time.Second * 3):
			wg.Done()
			t.Fatal("Message timed out")
		}
	}()

	time.Sleep(time.Millisecond * 100)
	assert.NoError(t, w.Update("test", "data"))

	wg.Wait()
}

func TestSubscribeWithRaiseOnlyNotOwn(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	defer client.Close()

	w := NewWatcher(client)
	defer w.Close()

	ch := make(chan string)
	w.SetUpdateCallback("test", func(msg string) {
		ch <- msg
	})

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		select {
		case _ = <-ch:
			wg.Done()
			t.Fatal("Message from own node was raised")
		case <-time.After(time.Second * 2):
			wg.Done()
		}
	}()

	time.Sleep(time.Millisecond * 100)
	assert.NoError(t, w.Update("test", "data"))
	wg.Wait()
}

func TestClose(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	w := NewWatcher(client, RaiseOwn(true))

	ch := make(chan string)
	w.SetUpdateCallback("test", func(msg string) {
		ch <- msg
	})

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		for {
			select {
			case res := <-ch:
				assert.Equal(t, "data1", res)
			case <-time.After(time.Second * 3):
				wg.Done()
			}
		}
	}()

	time.Sleep(time.Millisecond * 100)
	assert.NoError(t, w.Update("test", "data1"))
	assert.NoError(t, w.Close())
	assert.NoError(t, client.Close())
	assert.Error(t, w.Update("test", "data2"))

	wg.Wait()
}
