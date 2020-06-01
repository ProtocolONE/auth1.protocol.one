package mongo

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/env"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

const (
	collection = "user"
)

type UserRepository struct {
	db *mgo.Database
}

func New(env *env.Mongo) UserRepository {
	return UserRepository{
		db: env.DB,
	}
}

func (r UserRepository) FindByID(ctx context.Context, id string) (*entity.User, error) {
	p := &model{}
	if err := r.db.C(collection).FindId(bson.ObjectIdHex(id)).One(p); err != nil {
		return nil, err
	}

	return p.Convert(), nil
}
