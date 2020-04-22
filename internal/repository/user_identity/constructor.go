package user_identity

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/internal/env"
	"github.com/ProtocolONE/auth1.protocol.one/internal/repository/user_identity/mongo"
)

func New(env *env.Env) repository.UserIdentityRepository {
	return mongo.New(env.Store.Mongo)
}
