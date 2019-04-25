package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/persist"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/ory/hydra/sdk/go/hydra"
)

type InternalRegistry interface {
	Watcher() persist.Watcher
	MgoSession() database.Session
	HydraAdminApi() hydra.OAuth2API
	MfaService() proto.MfaService
	ApplicationService() ApplicationServiceInterface
	OneTimeTokenService() OneTimeTokenServiceInterface
	Mailer() MailerInterface
}
