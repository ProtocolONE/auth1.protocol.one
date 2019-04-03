package migrations

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/pkg/errors"
	"github.com/xakep666/mongo-migrate"
)

func init() {
	err := migrate.Register(
		func(db *mgo.Database) error {
			var err error
			var providers []*models.AppIdentityProvider

			err = db.C(database.TableAppIdentityProvider).Find(bson.M{
				"type": models.AppIdentityProviderTypePassword,
				"name": models.AppIdentityProviderNameDefault,
			}).All(&providers)
			if err != nil {
				return errors.Wrapf(err, "Unable to get providers with message: ", err)
			}

			for _, provider := range providers {
				selector := bson.M{"app_id": provider.ApplicationID}
				update := bson.M{"$set": bson.M{"identity_provider_id": provider.ID}}
				if _, err := db.C(database.TableUserIdentity).UpdateAll(selector, update); err != nil {
					return errors.Wrapf(err, "Unable to update users with message: ", err)
				}
			}

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
