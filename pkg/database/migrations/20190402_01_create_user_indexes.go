package migrations

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/globalsign/mgo"
	"github.com/pkg/errors"
	"github.com/xakep666/mongo-migrate"
)

func init() {
	err := migrate.Register(
		func(db *mgo.Database) error {
			var err error

			err = db.C(database.TableUserIdentity).EnsureIndex(mgo.Index{
				Name:       "Idx-AppId-ExternalId-Connection",
				Key:        []string{"app_id", "external_id", "connection"},
				Unique:     true,
				DropDups:   true,
				Background: true,
				Sparse:     false,
			})
			if err != nil {
				return errors.Wrapf(err, "Ensure user identity collection `Idx-AppId-ExternalId-Connection` index failed")
			}

			return nil
		},
		func(db *mgo.Database) error {
			if err := db.C(database.TableUserIdentity).DropIndexName("Idx-AppId-ExternalId-Connection"); err != nil {
				return errors.Wrapf(err, "Drop user identity collection `Idx-AppId-ExternalId-Connection` index failed")
			}

			return nil
		},
	)

	if err != nil {
		return
	}
}
