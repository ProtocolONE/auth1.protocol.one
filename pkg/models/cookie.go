package models

import (
	"github.com/gorilla/securecookie"
	"gopkg.in/mgo.v2/bson"
	"net/http"
)

type (
	CookieSettings struct {
		TTL  int
		Name string
	}

	Cookie struct {
		UserId        bson.ObjectId
		ApplicationId bson.ObjectId
	}
)

func NewCookie(a *Application, u *User) *Cookie {
	return &Cookie{
		ApplicationId: a.Id,
		UserId:        u.ID,
	}
}

func (c *Cookie) Crypt(cs *CookieSettings) (*http.Cookie, error) {
	cookieHandler := securecookie.New(
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32))
	encoded, err := cookieHandler.Encode(cs.Name, c)
	if err != nil {
		return nil, err
	}

	return &http.Cookie{
		Name:   cs.Name,
		Value:  encoded,
		Path:   "/",
		Secure: true,
		//Expires: time.Now().Add(time.Duration(cs.TTL)*time.Second),
		MaxAge: cs.TTL,
	}, nil
}

func (c *Cookie) Clear(cs *CookieSettings) *http.Cookie {
	return &http.Cookie{
		Name:   cs.Name,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
}
