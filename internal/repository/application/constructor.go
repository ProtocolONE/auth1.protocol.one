package application

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/internal/env"
	"github.com/ProtocolONE/auth1.protocol.one/internal/repository/application/mongo"
)

func New(env *env.Env) repository.ApplicationRepository {
	return mongo.New(env.Store.Mongo)
}
