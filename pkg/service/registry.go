package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/persist"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/globalsign/mgo"
	"github.com/ory/hydra/sdk/go/hydra"
)

type InternalRegistry interface {
	Watcher() persist.Watcher
	MgoSession() *mgo.Session
	HydraSDK() *hydra.CodeGenSDK
	MfaService() proto.MfaService
	ApplicationService() *ApplicationService
	OneTimeTokenService() *OneTimeTokenService
	Mailer() Mailer
}
