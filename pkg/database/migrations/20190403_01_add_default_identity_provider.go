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

			err = db.C(database.TableAppIdentityProvider).EnsureIndex(mgo.Index{
				Name:       "Idx-AppId-Type-Name",
				Key:        []string{"app_id", "type", "name"},
				Unique:     true,
				DropDups:   true,
				Background: true,
				Sparse:     false,
			})
			if err != nil {
				return errors.Wrapf(err, "Ensure application identity provider collection index `Idx-AppId-Type-Name` failed with message: ", err)
			}

			if _, err := db.C(database.TableAppIdentityProvider).RemoveAll(nil); err != nil {
				return errors.Wrapf(err, "Unable to remove application identity providers with message: ", err)
			}

			if err = db.C(database.TableApplication).Find(nil).All(&apps); err != nil {
				return errors.Wrapf(err, "Unable to get applications with message: ", err)
			}

			ipc := &models.AppIdentityProvider{
				ID:          bson.NewObjectId(),
				Type:        models.AppIdentityProviderTypePassword,
				Name:        models.AppIdentityProviderNameDefault,
				DisplayName: "Initial connection",
			}

			for _, app := range apps {
				ipc.ApplicationID = app.ID
				if err = db.C(database.TableAppIdentityProvider).Insert(ipc); err != nil {
					return errors.Wrapf(err, "Unable to add default application identity provider with message: %s", err)
				}
			}

			return nil
		},
		func(db *mgo.Database) error {
			if err := db.C(database.TableAppIdentityProvider).DropIndexName("Idx-AppId-Type-Name"); err != nil {
				return errors.Wrapf(err, "Drop application identity provider collection `Idx-AppId-Type-Name` index failed with message: %s", err)
			}

			if _, err := db.C(database.TableAppIdentityProvider).RemoveAll(nil); err != nil {
				return errors.Wrapf(err, "Unable to remove application identity providers with message: ", err)
			}

			return nil
		},
	)

	if err != nil {
		return
	}
}
