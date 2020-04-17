package user

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/internal/env"
	"github.com/ProtocolONE/auth1.protocol.one/internal/repository/user/mongo"
)

func New(env *env.Env) repository.UserRepository {
	return mongo.New(env.Store.Mongo)
}
