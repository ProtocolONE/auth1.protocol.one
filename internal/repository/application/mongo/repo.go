package mongo

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/env"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

const (
	collection = "application"
)

type ApplicationRepository struct {
	db *mgo.Database
}

func New(env *env.Mongo) ApplicationRepository {
	return ApplicationRepository{
		db: env.DB,
	}
}

func (r ApplicationRepository) FindByID(ctx context.Context, id string) (*entity.Application, error) {
	p := &model{}
	if err := r.db.C(collection).FindId(bson.ObjectIdHex(id)).One(p); err != nil {
		return nil, err
	}
	return p.Convert(), nil
}
