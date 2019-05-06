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

// DataLayer is an interface to access to the database struct.
type Database interface {
	C(name string) *mgo.Collection
}

// Collection is an interface to access to the collection struct.
type Collection interface {
	Find(query interface{}) *mgo.Query
	Count() (n int, err error)
	Insert(docs ...interface{}) error
	Remove(selector interface{}) error
	Update(selector interface{}, update interface{}) error
}

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
