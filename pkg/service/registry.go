package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/persist"
)

// InternalRegistry describes of methods the registry service.
type InternalRegistry interface {
	// Watcher creates and return watcher service.
	Watcher() persist.Watcher

	// MgoSession return the Mongo session.
	MgoSession() database.MgoSession

	// HydraAdminApi return the client of the Hydra administration api.
	HydraAdminApi() HydraAdminApi

	// MfaService return the client of MFA micro-service.
	MfaService() MfaApiInterface

	// GeoIp returns the client of GeoIP  micro-service.
	GeoIpService() GeoIp

	// ApplicationService return instance of the application service.
	ApplicationService() ApplicationServiceInterface

	// OneTimeTokenService return instance of the one time token service.
	OneTimeTokenService() OneTimeTokenServiceInterface

	// LauncherTokenService returns instance of the launcher token service
	LauncherTokenService() LauncherTokenServiceInterface

	// Mailer return client of the postman service.
	Mailer() MailerInterface
}
