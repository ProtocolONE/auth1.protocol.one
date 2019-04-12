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

			ipc := &models.AppIdentityProvider{
				Type:        models.AppIdentityProviderTypePassword,
				Name:        models.AppIdentityProviderNameDefault,
				DisplayName: models.AppIdentityProviderDisplayNameDefault,
			}

			for _, app := range apps {
				hasDefaultProvider := false
				for _, ip := range app.IdentityProviders {
					if ip.Name == models.AppIdentityProviderNameDefault && ip.Type == models.AppIdentityProviderTypePassword {
						hasDefaultProvider = true
					}
				}

				if hasDefaultProvider == false {
					ipc.ApplicationID = app.ID
					ipc.ID = bson.NewObjectId()
					app.IdentityProviders = append(app.IdentityProviders, ipc)

					if err = db.C(database.TableApplication).UpdateId(app.ID, app); err != nil {
						return errors.Wrapf(err, "Unable to update app with identity provider")
					}
				}
			}

			return nil
		},
		func(db *mgo.Database) error {
			var err error
			var apps []*models.Application

			if err = db.C(database.TableApplication).Find(nil).All(&apps); err != nil {
				return errors.Wrapf(err, "Unable to get applications")
			}

			for _, app := range apps {
				for i, ip := range app.IdentityProviders {
					if ip.Name == models.AppIdentityProviderNameDefault && ip.Type == models.AppIdentityProviderTypePassword {
						app.IdentityProviders = append(app.IdentityProviders[:i], app.IdentityProviders[i+1:]...)

						if err = db.C(database.TableApplication).UpdateId(app.ID, app); err != nil {
							return errors.Wrapf(err, "Unable to remove from app the identity provider")
						}
					}
				}
			}

			return nil
		},
	)

	if err != nil {
		return
	}
}
