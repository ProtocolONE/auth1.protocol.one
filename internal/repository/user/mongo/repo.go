package mongo

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/env"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

type UserRepository struct {
	col *mgo.Collection
}

func New(env *env.Mongo) UserRepository {
	return UserRepository{
		col: env.DB.C("user"),
	}
}

func (r UserRepository) FindByID(ctx context.Context, id entity.UserID) (*entity.User, error) {
	p := &model{}
	oid := bson.ObjectIdHex(string(id))
	if err := r.col.FindId(oid).One(p); err != nil {
		return nil, err
	}

	return p.Convert(), nil
}
