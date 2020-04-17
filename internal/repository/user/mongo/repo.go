package mongo

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/env"
	"github.com/globalsign/mgo"
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

func (r UserRepository) SetPassword(ctx context.Context, i *entity.User) error {
	return nil
}

func (r UserRepository) FindByID(ctx context.Context, id string) (*entity.User, error) {
	return nil, nil
}
