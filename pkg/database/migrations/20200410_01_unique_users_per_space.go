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

			iter := db.C(database.TableUser).Find(bson.M{}).Iter()
			var user models.User
			for iter.Next(&user) {
				var app = findapp(apps, user.AppID)
				user.SpaceID = app.SpaceId
				db.C(database.TableUser).UpdateId(user.ID, user)

			}
			if err := iter.Close(); err != nil {
				return errors.Wrap(err, "failed to close iterator")
			}



			if err := db.C(database.TableUser).DropIndexName("Idx-Username-AppId"); err != nil {
				return errors.Wrapf(err, "Drop user identity collection `Idx-Username-AppId` index failed")
			}

			db.C(database.TableUser).EnsureIndex(mgo.Index{
				Name:          "Idx-Username-SpaceId",
				Key:           []string{"username", "space_id"},
				PartialFilter: bson.M{"uniq_username": true},
				Unique:        true,
				Background:    true,
				Sparse:        false,
			})

			if err != nil {
				return errors.Wrapf(err, "Ensure user identity collection `Idx-Username-SpaceId` index failed")
			}

			return nil
		},
		func(db *mgo.Database) error {
			if err := db.C(database.TableUserIdentity).DropIndex("username", "space_id"); err != nil {
				return errors.Wrapf(err, "Drop user identity collection `Idx-Username-SpaceId` index failed")
			}

			return nil
		},
	)

	if err != nil {
		return
	}
}


func findapp(apps []*models.Application, id bson.ObjectId) *models.Application {
	for _, a := range  apps {
		if a.ID == id  {
			return a
		}
	}
	panic("not found")
}