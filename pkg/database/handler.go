package database

import (
	"auth-one-api/pkg/config"
	"github.com/globalsign/mgo"
	"net/url"
)

type (
	Handler struct {
		Name    string
		Session *mgo.Session
	}
)

func (h Handler) Clone() *mgo.Session {
	db := h.Session.Clone()

	return db
}

func NewConnection(c *config.DatabaseConfig) (*mgo.Session, error) {
	return mgo.Dial(BuildConnString(c))
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
