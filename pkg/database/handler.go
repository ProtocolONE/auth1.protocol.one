package database

import (
	"auth-one-api/pkg/config"
	"github.com/globalsign/mgo"
	"net/url"
	"time"
)

func NewConnection(c *config.DatabaseConfig) (*mgo.Session, error) {
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

func Migrate(db *mgo.Database, direction string) error {
	var err error

	/*migrate.SetDatabase(db)

	if direction == "up" {
		err = migrate.Up(migrate.AllAvailable)
	}

	if direction == "down" {
		err = migrate.Down(migrate.AllAvailable)
	}*/

	return err
}

func BuildConnString(c *config.DatabaseConfig) string {
	if c.Database == "" {
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
		Path:     c.Database,
		Host:     c.Host,
		User:     userInfo,
		RawQuery: vv.Encode(),
	}

	return u.String()
}
