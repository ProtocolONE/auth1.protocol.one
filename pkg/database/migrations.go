package database

import (
	"github.com/appleboy/mgo-migrate"
	"github.com/globalsign/mgo"
	"github.com/pkg/errors"
)

func MigrateDb(s *mgo.Session, dbName string) error {
	db := s.DB(dbName)

	migrations := []*migrate.Migration{{
		ID: "2019-04-02-00",
		Migrate: func(s *mgo.Session) error {
			err := db.C(TableUser).EnsureIndex(mgo.Index{
				Name:       "Idx-AppId-Email",
				Key:        []string{"app_id", "email"},
				Unique:     true,
				DropDups:   true,
				Background: true,
				Sparse:     false,
			})

			if err != nil {
				return errors.Wrap(err, "Ensure user collection index `Idx-AppId-Email` failed")
			}

			err = db.C(TableUserIdentity).EnsureIndex(mgo.Index{
				Name:       "Idx-AppId-ExternalId-Connection",
				Key:        []string{"app_id", "external_id", "connection"},
				Unique:     true,
				DropDups:   true,
				Background: true,
				Sparse:     false,
			})

			if err != nil {
				return errors.Wrap(err, "Ensure user identity collection `Idx-AppId-ExternalId-Connection` index failed")
			}

			return nil
		},
		Rollback: func(s *mgo.Session) error {
			if err := db.C(TableUser).DropIndex("Idx-AppId-Email"); err != nil {
				return errors.Wrap(err, "Drop user collection `Idx-AppId-Email` index failed")
			}

			if err := db.C(TableUserIdentity).DropIndex("Idx-AppId-ExternalId-Connection"); err != nil {
				return errors.Wrap(err, "Drop user identity collection `Idx-AppId-ExternalId-Connection` index failed")
			}

			return nil
		},
	}}

	m := migrate.New(s, dbName, migrate.DefaultOptions, migrations)
	if err := m.Migrate(); err != nil {
		if err = m.RollbackLast(); err != nil {
			return errors.Wrap(err, "Failed to rollback database migration")
		}

		return errors.Wrap(err, "Failed to migrate database")
	}

	return nil
}
