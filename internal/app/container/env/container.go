package env

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/env"
	"github.com/globalsign/mgo"
	"go.uber.org/fx"
)

func New() fx.Option {
	return fx.Provide(
		env.New,
	)
}

// todo: it's temporary dependency fix
func NewDB(db *mgo.Database) func() fx.Option {
	return func() fx.Option {
		return fx.Provide(
			func() *mgo.Database {
				return db
			},
		)
	}
}
