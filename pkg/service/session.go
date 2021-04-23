package service

import (
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"net/http"
)

// SessionService describes of methods for the session service.
type SessionService interface {
	// Get returns value from session by parameter name.
	Get(echo.Context, string) (interface{}, error)

	// Set sets the value in the session.
	Set(echo.Context, string, interface{}) error
}

// SessionSettings is the session service.
type SessionSettings struct {
	name string
}

// NewSessionService return new session service.
func NewSessionService(name string) SessionService {
	return &SessionSettings{name: name}
}

func (s *SessionSettings) Get(ctx echo.Context, name string) (interface{}, error) {
	sess, err := session.Get(s.name, ctx)
	if err != nil {
		return nil, err
	}
	return sess.Values[name], nil
}

func (s *SessionSettings) Set(ctx echo.Context, name string, value interface{}) error {
	sess, err := session.Get(s.name, ctx)
	if err != nil {
		return err
	}
	sess.Values[name] = value
	sess.Options = &sessions.Options{
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
	}

	if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
		return err
	}
	return nil
}
