package mongo

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/env"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

type ApplicationRepository struct {
	col *mgo.Collection
}

func New(env *env.Mongo) ApplicationRepository {
	return ApplicationRepository{
		col: env.DB.C("application"),
	}
}

func (r ApplicationRepository) Find(ctx context.Context) ([]*entity.Application, error) {
	var m []model
	if err := r.col.Find(nil).All(&m); err != nil {
		return nil, err
	}

	var result []*entity.Application
	for i := range m {
		result = append(result, m[i].Convert())
	}

	return result, nil
}

func (r ApplicationRepository) FindByID(ctx context.Context, id entity.AppID) (*entity.Application, error) {
	var (
		p   model
		oid = bson.ObjectIdHex(string(id))
	)
	if err := r.col.FindId(oid).One(&p); err != nil {
		return nil, err
	}
	return p.Convert(), nil
}
