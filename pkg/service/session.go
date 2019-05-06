package service

import (
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

type SessionService interface {
	Get(echo.Context, string) (interface{}, error)
	Set(echo.Context, string, interface{}) error
}

type SessionSettings struct {
	name string
}

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
	if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
		return err
	}
	return nil
}
