package mongo

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/env"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

const (
	collection = "profiles"
)

type ProfileRepository struct {
	db *mgo.Database
}

func New(env *env.Mongo) ProfileRepository {
	return ProfileRepository{
		db: env.DB,
	}
}

func (r ProfileRepository) Create(ctx context.Context, i *entity.Profile) error {
	model, err := newModel(i)
	if err != nil {
		return err
	}

	if err := r.db.C(collection).Insert(model); err != nil {
		return err
	}

	*i = *model.Convert()
	return nil
}

func (r ProfileRepository) Update(ctx context.Context, i *entity.Profile) error {
	model, err := newModel(i)
	if err != nil {
		return err
	}
	if err := r.db.C(collection).UpdateId(model.ID, model); err != nil {
		return err
	}

	*i = *model.Convert()
	return nil
}

func (r ProfileRepository) FindByID(ctx context.Context, id string) (*entity.Profile, error) {
	p := &model{}
	if err := r.db.C(collection).FindId(id).One(p); err != nil {
		return nil, err
	}

	return p.Convert(), nil
}

func (r ProfileRepository) FindByUserID(ctx context.Context, userID string) (*entity.Profile, error) {
	p := &model{}
	if err := r.db.C(collection).Find(bson.M{"user_id": bson.ObjectIdHex(userID)}).One(p); err != nil {
		if err == mgo.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	return p.Convert(), nil
}
