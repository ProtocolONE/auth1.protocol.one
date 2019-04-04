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

			err = db.C(database.TableAppPasswordSettings).EnsureIndex(mgo.Index{
				Name:       "Idx-AppId",
				Key:        []string{"app_id"},
				Unique:     true,
				DropDups:   true,
				Background: true,
				Sparse:     false,
			})
			if err != nil {
				return errors.Wrapf(err, "Ensure password settings collection index `Idx-AppId` failed")
			}

			if err = db.C(database.TableApplication).Find(nil).All(&apps); err != nil {
				return errors.Wrapf(err, "Unable to get applications")
			}

			ps := &models.PasswordSettings{
				BcryptCost:     models.PasswordBcryptCostDefault,
				Min:            models.PasswordMinDefault,
				Max:            models.PasswordMaxDefault,
				RequireNumber:  models.PasswordRequireNumberDefault,
				RequireUpper:   models.PasswordRequireUpperDefault,
				RequireSpecial: models.PasswordRequireSpecialDefault,
				TokenLength:    models.PasswordTokenLengthDefault,
				TokenTTL:       models.PasswordTokenTTLDefault,
			}

			for _, app := range apps {
				ps.ApplicationID = app.ID
				if err = db.C(database.TableAppPasswordSettings).Insert(ps); err != nil {
					return errors.Wrapf(err, "Unable to add default password settings")
				}
			}

			return nil
		},
		func(db *mgo.Database) error {
			if err := db.C(database.TableAppPasswordSettings).DropIndex("app_id"); err != nil {
				return errors.Wrapf(err, "Drop password settings collection `Idx-AppId` index failed")
			}

			if _, err := db.C(database.TableAppPasswordSettings).RemoveAll(nil); err != nil {
				return errors.Wrapf(err, "Unable to remove password settings")
			}

			return nil
		},
	)

	if err != nil {
		return
	}
}
