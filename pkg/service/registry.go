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
	HydraAdminApi() hydra.OAuth2API
	MfaService() proto.MfaService
	ApplicationService() ApplicationServiceInterface
	OneTimeTokenService() OneTimeTokenServiceInterface
	Mailer() MailerInterface
}
