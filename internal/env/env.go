package env

import "github.com/globalsign/mgo"

type Env struct {
	Store *Store
}

func New(db *mgo.Database) (*Env, error) {
	storeEnv, err := newStore(db)
	if err != nil {
		return nil, err
	}

	return &Env{
		Store: storeEnv,
	}, nil
}
