package mongo

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/env"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

type UserIdentityRepository struct {
	col *mgo.Collection
}

func New(env *env.Mongo) UserIdentityRepository {
	return UserIdentityRepository{
		col: env.DB.C("user_identity"),
	}
}

func (r UserIdentityRepository) FindByID(ctx context.Context, id entity.UserIdentityID) (*entity.UserIdentity, error) {
	var result model
	oid := bson.ObjectIdHex(string(id))
	if err := r.col.FindId(oid).One(&result); err != nil {
		if err == mgo.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	return result.Convert(), nil
}

func (r UserIdentityRepository) FindForUser(ctx context.Context, userID entity.UserID) ([]*entity.UserIdentity, error) {
	var list []*model
	if err := r.col.Find(bson.M{
		"user_id": bson.ObjectIdHex(string(userID)),
	}).All(&list); err != nil {
		return nil, err
	}
	var resp []*entity.UserIdentity
	for _, i := range list {
		resp = append(resp, i.Convert())
	}

	return resp, nil
}

func oid(v string) bson.ObjectId {
	return bson.ObjectIdHex(v)
}

func (r UserIdentityRepository) FindByProviderAndUser(ctx context.Context, idProviderID entity.IdentityProviderID, userID entity.UserID) (*entity.UserIdentity, error) {
	ui := &model{}
	if err := r.col.Find(bson.M{
		"identity_provider_id": bson.ObjectIdHex(string(idProviderID)),
		"user_id":              bson.ObjectIdHex(string(userID)),
	}).One(ui); err != nil {
		if err == mgo.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	return ui.Convert(), nil
}

func (r UserIdentityRepository) Update(ctx context.Context, i *entity.UserIdentity) error {
	model, err := newModel(i)
	if err != nil {
		return err
	}
	if err := r.col.UpdateId(model.ID, model); err != nil {
		return err
	}

	*i = *model.Convert()
	return nil
}
