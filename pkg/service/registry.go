package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/persist"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
)

type InternalRegistry interface {
	Watcher() persist.Watcher
	MgoSession() database.Session
	HydraAdminApi() HydraAdminApi
	MfaService() proto.MfaService
	ApplicationService() ApplicationServiceInterface
	OneTimeTokenService() OneTimeTokenServiceInterface
	Mailer() MailerInterface
}
