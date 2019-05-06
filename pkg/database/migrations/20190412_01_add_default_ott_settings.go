package migrations

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
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
				app.OneTimeTokenSettings = &models.OneTimeTokenSettings{
					Length: 64,
					TTL:    3600,
				}
				if err := db.C(database.TableApplication).UpdateId(app.ID, app); err != nil {
					return errors.Wrap(err, "Unable to update application")
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
