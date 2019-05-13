package database

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/globalsign/mgo"
	"net/url"
	"time"
)

// Session is an interface to access to the Session struct.
type MgoSession interface {
	DB(name string) *mgo.Database
	Copy() *mgo.Session
	Close()
}

// NewConnection establishes a new session to the database.
func NewConnection(c *config.Database) (MgoSession, error) {
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

// BuildConnString creates a database connection string based on configuration parameters.
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
