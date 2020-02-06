package migrations

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/globalsign/mgo"
	"github.com/pkg/errors"
	"github.com/xakep666/mongo-migrate"
	"github.com/globalsign/mgo/bson"	
)

func init() {
	err := migrate.Register(
		func(db *mgo.Database) error {
			var err error

			db.C(database.TableUser).EnsureIndex(mgo.Index{
				Name: "Idx-Username-AppId",
				Key: []string{"username", "app_id"},
				PartialFilter: bson.M{"unique_username": true},
				Unique: true,
				Background: true,
				Sparse: false,
			})

			if err != nil {
				return errors.Wrapf(err, "Ensure user identity collection `Idx-Username-AppId` index failed")
			}

			return nil
		},
		func(db *mgo.Database) error {
			if err := db.C(database.TableUserIdentity).DropIndex("username", "app_id"); err != nil {
				return errors.Wrapf(err, "Drop user identity collection `Idx-AppId-ExternalId-Connection` index failed")
			}

			return nil
		},
	)

	if err != nil {
		return
	}
}
