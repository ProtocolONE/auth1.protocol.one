package env

import (
	"github.com/globalsign/mgo"
)

type Store struct {
	Mongo *Mongo
}

type Mongo struct {
	DB *mgo.Database
}

func newStore(db *mgo.Database) (*Store, error) {
	mgo, err := newMongo(db)
	if err != nil {
		return nil, err
	}

	return &Store{
		Mongo: mgo,
	}, nil
}

func newMongo(db *mgo.Database) (*Mongo, error) {
	return &Mongo{
		DB: db,
	}, nil
}
