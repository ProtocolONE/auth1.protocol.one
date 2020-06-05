package migrations

import (
	"github.com/globalsign/mgo"
	"github.com/xakep666/mongo-migrate"
)

// DEPRICATED

func init() {
	migrate.Register(
		func(db *mgo.Database) error {
			return nil
		},
		func(db *mgo.Database) error {
			return nil
		},
	)
}
