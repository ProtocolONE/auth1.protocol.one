package database

import (
	"github.com/globalsign/mgo"
	"sync"
	"time"
)

const PingInterval = 1 * time.Second

type ConnectionPool struct {
	session      *mgo.Session
	sessions     []*mgo.Session
	sessionIndex int
	mu           sync.Mutex
	quit         chan struct{}
	wg           sync.WaitGroup
	closed       bool
}

func NewConnectionPool(s *mgo.Session, maxSessions int) *ConnectionPool {
	p := &ConnectionPool{
		sessions: make([]*mgo.Session, maxSessions),
		session:  s.Copy(),
		quit:     make(chan struct{}),
	}

	go func() {
		p.wg.Add(1)
		timer := time.NewTimer(PingInterval)

		for {
			select {
			case <-p.quit:
				p.wg.Done()
				return
			case <-timer.C:
				p.checkAlive()
			}
		}
	}()

	return p
}

func (p *ConnectionPool) Session() *mgo.Session {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		panic("Session called on closed Pool")
	}

	s := p.sessions[p.sessionIndex]
	if s == nil {
		s = p.session.Copy()
		p.sessions[p.sessionIndex] = s
	}

	p.sessionIndex = (p.sessionIndex + 1) % len(p.sessions)
	return s.Clone()
}

func (p *ConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	close(p.quit)
	p.wg.Wait()

	p.closed = true
	p.closeSessions()
	p.session.Close()
}

func (p *ConnectionPool) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.closeSessions()
}

func (p *ConnectionPool) closeSessions() {
	for i, session := range p.sessions {
		if session != nil {
			session.Close()
			p.sessions[i] = nil
		}
	}
}

func (p *ConnectionPool) checkAlive() {
	func() {
		session := p.Session()
		if session.Ping() != nil {
			p.Reset()
		}
		session.Close()
	}()
}
