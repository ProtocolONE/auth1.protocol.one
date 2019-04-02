package database

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/globalsign/mgo"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestConnectionPool_Session(t *testing.T) {
	session := createConnection(t)
	defer session.Close()

	pool := NewConnectionPool(session, 2)
	defer pool.Close()

	// Obtain a session from the pool, then kill its connection
	// so we can be sure that the next session is using a different
	// connection
	s0 := pool.Session()

	assert.NoError(t, s0.Ping())
	s0.Close()
	assert.Panics(t, func() {
		s0.Ping()
	})

	// The next session should still work.
	s1 := pool.Session()
	defer s1.Close()
	assert.NoError(t, s1.Ping())

	// The third session should cycle back to the first
	// and not fail.
	s2 := pool.Session()
	defer s2.Close()
	assert.NoError(t, s2.Ping())

	// Resetting the pool should cause new sessions
	// to work again.
	pool.Reset()
	s3 := pool.Session()
	defer s3.Close()

	assert.NoError(t, s3.Ping())
	s4 := pool.Session()
	defer s4.Close()
	assert.NoError(t, s4.Ping())
}

func TestConnectionPool_ClosingPoolDoesNotClosePreviousSessions(t *testing.T) {
	session := createConnection(t)
	defer session.Close()

	pool := NewConnectionPool(session, 2)
	defer pool.Close()

	s0 := pool.Session()
	defer s0.Close()
	pool.Close()
	assert.NoError(t, s0.Ping())
}

func TestConnectionPool_PanicOnSessionOnClosedPool(t *testing.T) {
	session := createConnection(t)
	defer session.Close()

	pool := NewConnectionPool(session, 2)
	defer pool.Close()

	pool.Close()
	assert.Panics(t, func() {
		pool.Session()
	})
}

func TestConnectionPool_CheckAlive(t *testing.T) {
	session := createConnection(t)
	defer session.Close()

	pool := NewConnectionPool(session, 1)
	defer pool.Close()

	s0 := pool.Session()
	defer s0.Close()
	assert.NoError(t, s0.Ping())

	time.Sleep(2 * PingInterval)

	s2 := pool.Session()
	defer s2.Close()
	assert.NoError(t, s2.Ping())
}

func createConnection(t *testing.T) *mgo.Session {
	t.Helper()

	cfg, err := config.Load()
	if err != nil {
		t.Fatal("Failed to load config")
	}

	session, err := NewConnection(&cfg.Database)
	if err != nil {
		t.Fatal("Failed to init session")
	}

	return session
}
