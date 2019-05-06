package migrations

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/globalsign/mgo"
	"github.com/xakep666/mongo-migrate"
)

func init() {
	err := migrate.Register(
		func(db *mgo.Database) error {
			db.C(database.TableUserIdentity).DropIndexName("Idx-AppId-ExternalId-Connection")
			db.C(database.TableAppIdentityProvider).DropIndexName("Idx-AppId-Type-Name")

			db.C(database.TableAppIdentityProvider).RemoveAll(nil)

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
