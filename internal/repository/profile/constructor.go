package profile

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/internal/env"
	"github.com/ProtocolONE/auth1.protocol.one/internal/repository/profile/mongo"
)

func New(env *env.Env) repository.ProfileRepository {
	return mongo.New(env.Store.Mongo)
}
