package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/persist"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/persist/redis"
	"github.com/go-redis/redis"
)

type RegistryBase struct {
	redis   *redis.Client
	session database.MgoSession
	as      ApplicationServiceInterface
	ott     OneTimeTokenServiceInterface
	watcher persist.Watcher
	hydra   HydraAdminApi
	mfa     MfaApiInterface
	mailer  MailerInterface
}

type RegistryConfig struct {
	MgoSession    database.MgoSession
	RedisClient   *redis.Client
	MfaService    MfaApiInterface
	HydraAdminApi HydraAdminApi
	Mailer        MailerInterface
}

func NewRegistryBase(config *RegistryConfig) InternalRegistry {
	return &RegistryBase{
		session: config.MgoSession,
		redis:   config.RedisClient,
		hydra:   config.HydraAdminApi,
		mfa:     config.MfaService,
		mailer:  config.Mailer,
	}
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

func (r *RegistryBase) Mailer() MailerInterface {
	return r.mailer
}

func (r *RegistryBase) ApplicationService() ApplicationServiceInterface {
	if r.as == nil {
		r.as = NewApplicationService(r)
	}

	return r.as
}

func (r *RegistryBase) OneTimeTokenService() OneTimeTokenServiceInterface {
	if r.ott == nil {
		r.ott = NewOneTimeTokenService(r.redis)
	}

	return r.ott
}
