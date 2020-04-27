package mongo

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/env"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

const (
	collection = "user_identity"
)

type UserIdentityRepository struct {
	db *mgo.Database
}

func New(env *env.Mongo) UserIdentityRepository {
	return UserIdentityRepository{
		db: env.DB,
	}
}

func (r UserIdentityRepository) GetByID(ctx context.Context, id string) (*entity.UserIdentity, error) {
	m := &model{}
	if err := r.db.C(collection).FindId(bson.ObjectIdHex(id)).One(m); err != nil {
		if err == mgo.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	return m.Convert(), nil
}

func (r UserIdentityRepository) FindIdentities(ctx context.Context, appID, userID string) ([]*entity.UserIdentity, error) {
	var list []*model
	if err := r.db.C(collection).Find(bson.M{
		"user_id": bson.ObjectIdHex(userID),
		"app_id":  bson.ObjectIdHex(appID),
	}).All(&list); err != nil {
		return nil, err
	}
	var resp []*entity.UserIdentity
	for _, i := range list {
		resp = append(resp, i.Convert())
	}

	return resp, nil
}

func (r UserIdentityRepository) FindIdentity(ctx context.Context, appID, identityProviderID, userID string) (*entity.UserIdentity, error) {
	ui := &model{}
	if err := r.db.C(collection).Find(bson.M{
		"app_id":               bson.ObjectIdHex(appID),
		"identity_provider_id": bson.ObjectIdHex(identityProviderID),
		"user_id":              bson.ObjectIdHex(userID),
	}).One(ui); err != nil {
		if err == mgo.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	return ui.Convert(), nil
}

func (r UserIdentityRepository) FindIdentitiesWithType(ctx context.Context, appID, userID, identityType string) ([]*entity.UserIdentity, error) {
	var list []*model
	if err := r.db.C(collection).Find(bson.M{
		"user_id": bson.ObjectIdHex(userID),
		"app_id":  bson.ObjectIdHex(appID),
		"type":    identityType,
	}).All(&list); err != nil {
		return nil, err
	}
	var resp []*entity.UserIdentity
	for _, i := range list {
		resp = append(resp, i.Convert())
	}

	return resp, nil
}

func (r UserIdentityRepository) Update(ctx context.Context, i *entity.UserIdentity) error {
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
