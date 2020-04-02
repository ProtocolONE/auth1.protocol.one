package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/persist"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/persist/redis"
	"github.com/go-redis/redis"
)

// RegistryBase contains common services.
type RegistryBase struct {
	redis   *redis.Client
	session database.MgoSession
	as      ApplicationServiceInterface
	ott     OneTimeTokenServiceInterface
	lts     LauncherTokenServiceInterface
	lss     LauncherServerService
	watcher persist.Watcher
	hydra   HydraAdminApi
	mfa     MfaApiInterface
	geo     GeoIp
	mailer  MailerInterface
	cent    CentrifugoServiceInterface
}

// RegistryConfig contains the configuration parameters of Registry
type RegistryConfig struct {
	// MgoSession is the interface for the Mongo session.
	MgoSession database.MgoSession

	// RedisClient is the client of the Redis.
	RedisClient *redis.Client

	// GeoIpService is the interface for the GeoIp micro-service.
	GeoIpService GeoIp

	// MfaService is the interface for the MFA micro-service.
	MfaService MfaApiInterface

	// HydraAdminApi is the interface for the Hydra administration api.
	HydraAdminApi HydraAdminApi

	// Mailer is the interface for the postman.
	Mailer MailerInterface

	// CentrifugoService
	CentrifugoService CentrifugoServiceInterface
}

// NewRegistryBase creates new registry service.
func NewRegistryBase(config *RegistryConfig) InternalRegistry {
	r := &RegistryBase{
		session: config.MgoSession,
		redis:   config.RedisClient,
		hydra:   config.HydraAdminApi,
		mfa:     config.MfaService,
		mailer:  config.Mailer,
		geo:     config.GeoIpService,
		ott:     NewOneTimeTokenService(config.RedisClient),
		lts:     NewLauncherTokenService(config.RedisClient),
		lss:     NewLauncherServerService(),
		cent:    config.CentrifugoService,
	}
	r.as = NewApplicationService(r)

	return r
}

func (r *RegistryBase) Watcher() persist.Watcher {
	if r.watcher == nil {
		r.watcher = rediswatcher.NewWatcher(r.redis)
	}

	return r.watcher
}

func (r *RegistryBase) MgoSession() database.MgoSession {
	return r.session
}

func (r *RegistryBase) HydraAdminApi() HydraAdminApi {
	return r.hydra
}

func (r *RegistryBase) MfaService() MfaApiInterface {
	return r.mfa
}

func (r *RegistryBase) GeoIpService() GeoIp {
	return r.geo
}

func (r *RegistryBase) Mailer() MailerInterface {
	return r.mailer
}

func (r *RegistryBase) ApplicationService() ApplicationServiceInterface {
	return r.as
}

func (r *RegistryBase) OneTimeTokenService() OneTimeTokenServiceInterface {
	return r.ott
}

func (r *RegistryBase) CentrifugoService() CentrifugoServiceInterface {
	return r.cent
}

func (r *RegistryBase) LauncherTokenService() LauncherTokenServiceInterface {
	return r.lts
}

func (r *RegistryBase) LauncherServer() LauncherServerService {
	return r.lss
}
