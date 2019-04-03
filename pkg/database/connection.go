package database

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/globalsign/mgo"
	"net/url"
	"time"
)

func NewConnection(c *config.Database) (*mgo.Session, error) {
	info, err := mgo.ParseURL(BuildConnString(c))
	if err != nil {
		return nil, err
	}

	info.Timeout = 10 * time.Second
	session, err := mgo.DialWithInfo(info)

	if err == nil {
		session.SetSyncTimeout(1 * time.Minute)
		session.SetSocketTimeout(1 * time.Minute)
	}

	return session, err
}

func BuildConnString(c *config.Database) string {
	if c.Name == "" {
		return ""
	}

	vv := url.Values{}

	var userInfo *url.Userinfo

	if c.User != "" {
		if c.Password == "" {
			userInfo = url.User(c.User)
		} else {
			userInfo = url.UserPassword(c.User, c.Password)
		}
	}

	u := url.URL{
		Scheme:   "mongodb",
		Path:     c.Name,
		Host:     c.Host,
		User:     userInfo,
		RawQuery: vv.Encode(),
	}

	return u.String()
}
