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

func NewCookie(app *Application, user *User) *Cookie {
	return &Cookie{
		ApplicationId: app.ID,
		UserId:        user.ID,
	}
}

func (c *Cookie) Crypt(cookieSettings *CookieSettings) (*http.Cookie, error) {
	cookieHandler := securecookie.New(
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32))
	encoded, err := cookieHandler.Encode(cookieSettings.Name, c)
	if err != nil {
		return nil, err
	}

	return &http.Cookie{
		Name:   cookieSettings.Name,
		Value:  encoded,
		Path:   "/",
		Secure: true,
		//Expires: time.Now().Add(time.Duration(cs.TTL)*time.Second),
		MaxAge: cookieSettings.TTL,
	}, nil
}

func (c *Cookie) Clear(cookieSettings *CookieSettings) *http.Cookie {
	return &http.Cookie{
		Name:   cookieSettings.Name,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
}
