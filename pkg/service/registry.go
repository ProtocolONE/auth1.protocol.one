package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/persist"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/globalsign/mgo"
	h "github.com/ory/hydra-legacy-sdk"
)

type InternalRegistry interface {
	Watcher() persist.Watcher
	MgoSession() *mgo.Session
	HydraSDK() *h.CodeGenSDK
	MfaService() proto.MfaService
	ApplicationService() *ApplicationService
	OneTimeTokenService() *OneTimeTokenService
	Mailer() Mailer
}
