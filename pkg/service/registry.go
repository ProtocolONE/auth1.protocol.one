package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/persist"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/globalsign/mgo"
)

type InternalRegistry interface {
	Watcher() persist.Watcher
	MgoSession() *mgo.Session
	HydraAdminApi() HydraAdminApi
	MfaService() proto.MfaService
	ApplicationService() *ApplicationService
	OneTimeTokenService() *OneTimeTokenService
	Mailer() Mailer
}
