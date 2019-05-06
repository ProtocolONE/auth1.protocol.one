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
			var apps []*models.Application

			if err = db.C(database.TableApplication).Find(nil).All(&apps); err != nil {
				return errors.Wrapf(err, "Unable to get applications")
			}

			for _, app := range apps {
				for _, ip := range app.IdentityProviders {
					if ip.Name == models.AppIdentityProviderNameDefault && ip.Type == models.AppIdentityProviderTypePassword {
						selector := bson.M{"app_id": ip.ApplicationID}
						update := bson.M{"$set": bson.M{"identity_provider_id": ip.ID}}
						if _, err := db.C(database.TableUserIdentity).UpdateAll(selector, update); err != nil {
							return errors.Wrapf(err, "Unable to update users")
						}
					}
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
