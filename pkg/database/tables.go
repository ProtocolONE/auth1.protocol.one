package database

const (
	TableSpace               = "space"
	TableApplication         = "application"
	TableAppIdentityProvider = "application_identity_provider"
	TableUser                = "user"
	TableUserIdentity        = "user_identity"
	TableUserIdentityData    = "user_identity_data"
	TableAuthLog             = "auth_log"
	TableApplicationMfa      = "application_mfa"
	TableUserMfa             = "user_mfa"

	// removed (normalization in auth_log not needed)
	TableUserAgent = "user_agent"
	TableUserIP    = "user_ip"
)
