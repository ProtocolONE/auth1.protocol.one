package migrations

import (
	"github.com/globalsign/mgo"
	"github.com/xakep666/mongo-migrate"
)

func init() {
	err := migrate.Register(
		func(db *mgo.Database) error {
			// removed (normalization in auth_log not needed)
			db.C("user_agent").DropCollection()
			db.C("user_ip").DropCollection()

			return nil
		},
		func(db *mgo.Database) error {
			return nil
		},
	)

	if err != nil {
		return
	}
}
