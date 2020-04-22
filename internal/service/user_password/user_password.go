package user_password

import (
	"context"
	"errors"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/service"
	"github.com/ProtocolONE/auth1.protocol.one/internal/service/user_password/utils"
	"github.com/ProtocolONE/auth1.protocol.one/internal/service/user_password/validator"
)

type Service struct {
	ServiceParams
}

var ErrPasswordDoesNotPassRequirement = errors.New("password does not pass requirement")
var ErrIdentityProviderNotFound = errors.New("identity provider not found")

func (s Service) SetPassword(ctx context.Context, data service.SetPasswordData) error {
	// extract app & load password settings
	app, err := s.ApplicationService.GetByID(ctx, data.AppID)
	if err != nil {
		return err
	}

	// validate new password
	if !validator.IsPasswordValid(app, data.PasswordNew) {
		return ErrPasswordDoesNotPassRequirement
	}

	ip := utils.GetPasswordIdentityProvider(*app)
	if ip == nil {
		return ErrIdentityProviderNotFound
	}

	// find user identity for password identity provider
	ui, err := s.UserIdentityService.GetIdentity(ctx, &service.GetIdentityData{
		AppID:              data.AppID,
		IdentityProviderID: ip.ID,
		UserID:             data.UserID,
	})
	if err != nil {
		return err
	}

	// bcrypt password
	be := utils.NewBcryptEncryptor(utils.CryptConfig{Cost: app.PasswordSettings.BcryptCost})
	credential, err := be.Digest(data.PasswordNew)
	if err != nil {
		return err
	}

	// set user identity credential = password and save
	err = s.UserIdentityService.UpdateCredential(ctx, &service.UpdateUserIdentityCredentialData{
		ID:         ui.ID,
		Credential: &credential,
	})

	return err
}
