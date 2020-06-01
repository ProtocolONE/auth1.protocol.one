package utils

import "github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"

func GetPasswordIdentityProvider(app entity.Application) *entity.IdentityProvider {
	for _, ip := range app.IdentityProviders {
		if ip.Type == entity.AppIdentityProviderTypePassword && ip.Name == entity.AppIdentityProviderNameDefault {
			return ip
		}
	}

	return nil
}
