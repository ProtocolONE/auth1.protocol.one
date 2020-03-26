package service

import (
	"bytes"
	"encoding/json"
	"log"
	"time"

	"github.com/gorilla/websocket"
)

type LauncherServerService interface {
	InProgress(loginChallenge string)
	Success(loginChallenge, url string)
	Register(c *LauncherClient)
	UnRegister(c *LauncherClient)
}

type LauncherClient struct {
	// LoginChallenge
	loginChallenge string

	// The websocket connection.
	conn *websocket.Conn

	// Buffered channel of outbound messages.
	send chan []byte

	// LauncherServer
	srv LauncherServerService

	// Closed closed on websocket.close
	closed chan bool
}

func NewLauncherClient(loginChallenge string, conn *websocket.Conn, srv LauncherServerService) *LauncherClient {
	return &LauncherClient{
		loginChallenge: loginChallenge,
		conn:           conn,
		send:           make(chan []byte),
		srv:            srv,
		closed:         make(chan bool),
	}
}

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

var (
	newline  = []byte{'\n'}
	space    = []byte{' '}
	Upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
)

func (c *LauncherClient) Read() {
	defer func() {
		c.srv.UnRegister(c)
		c.conn.Close()
		close(c.closed)
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}
		message = bytes.TrimSpace(bytes.Replace(message, newline, space, -1))
		// void
	}
}

func (c *LauncherClient) Write() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued chat messages to the current websocket message.
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write(newline)
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *LauncherClient) Await() {
	<-c.closed
}

type LauncherMessage struct {
	LoginChallenge string `json:"-"`
	Status         string `json:"status"`
	URL            string `json:"url"`
}

func (m *LauncherMessage) Marshal() []byte {
	msg, _ := json.Marshal(*m)
	return msg
}

type LauncherServer struct {
	// Registered clients.
	clients map[*LauncherClient]bool

	// Register requests from the clients.
	register chan *LauncherClient

	// Unregister requests from clients.
	unregister chan *LauncherClient

	// Notify send message to client
	notify chan *LauncherMessage
}

func (s *LauncherServer) Run() {
	for {
		select {
		case client := <-s.register:
			s.clients[client] = true
		case client := <-s.unregister:
			if _, ok := s.clients[client]; ok {
				delete(s.clients, client)
				close(client.send)
			}
		case notification := <-s.notify:
			for client := range s.clients {
				if client.loginChallenge == notification.LoginChallenge {
					client.send <- notification.Marshal()
				}
			}
		}
	}
}

func (s *LauncherServer) InProgress(loginChallenge string) {
	for c, _ := range s.clients {
		if c.loginChallenge == loginChallenge {
			m := LauncherMessage{
				LoginChallenge: loginChallenge,
				Status:         "in_progress",
			}
			c.send <- m.Marshal()
			break
		}
	}
}

func (s *LauncherServer) Success(loginChallenge, url string) {
	for c, _ := range s.clients {
		if c.loginChallenge == loginChallenge {
			m := LauncherMessage{
				LoginChallenge: loginChallenge,
				Status:         "success",
				URL:            url,
			}
			c.send <- m.Marshal()
			break
		}
	}
}

func (s *LauncherServer) Register(c *LauncherClient) {
	s.register <- c
}

func (s *LauncherServer) UnRegister(c *LauncherClient) {
	s.unregister <- c
}

func NewLauncherServerService() LauncherServerService {
	lss := &LauncherServer{
		clients:    map[*LauncherClient]bool{},
		register:   make(chan *LauncherClient),
		unregister: make(chan *LauncherClient),
		notify:     make(chan *LauncherMessage),
	}
	go lss.Run()
	return lss
}
