package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/persist"
)

type InternalRegistry interface {
	Watcher() persist.Watcher
	MgoSession() database.MgoSession
	HydraAdminApi() HydraAdminApi
	MfaService() MfaApiInterface
	ApplicationService() ApplicationServiceInterface
	OneTimeTokenService() OneTimeTokenServiceInterface
	Mailer() MailerInterface
}
