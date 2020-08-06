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

func New(env *env.Mongo) *UserRepository {
	return &UserRepository{
		col: env.DB.C("user"),
	}
}

func (r *UserRepository) Update(ctx context.Context, user *entity.User) error {
	model, err := newModel(user)
	if err != nil {
		return err
	}

	if err := r.col.UpdateId(model.ID, model); err != nil {
		return err
	}

	*user = *model.Convert()
	return nil
}

func (r *UserRepository) Find(ctx context.Context) ([]*entity.User, error) {
	var m []model
	if err := r.col.Find(nil).All(&m); err != nil {
		return nil, err
	}

	var result []*entity.User
	for i := range m {
		result = append(result, m[i].Convert())
	}

	return result, nil
}

func (r *UserRepository) FindByID(ctx context.Context, id entity.UserID) (*entity.User, error) {
	p := &model{}
	oid := bson.ObjectIdHex(string(id))
	if err := r.col.FindId(oid).One(p); err != nil {
		if err == mgo.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	return p.Convert(), nil
}
