package password_manager

import (
	"context"
	"errors"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	ServiceParams
}

var ErrPasswordTooWeak = errors.New("password doesn't meet requirements")
var ErrPasswordMismatch = errors.New("password doesn't match")

func (s *Service) Compare(hashedPassword string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func (s *Service) Digest(password string, cost int) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(hashedPassword), err
}

func (s *Service) ChangePassword(ctx context.Context, userId entity.UserID, old, new string) error {
	user, err := s.Users.FindByID(ctx, userId)
	if err != nil {
		return err
	}

	space, err := s.Spaces.FindByID(ctx, user.SpaceID)
	if err != nil {
		return err
	}

	if !space.PasswordSettings.IsValid(new) {
		return ErrPasswordTooWeak
	}

	provider := space.DefaultIDProvider()

	identity, err := s.UserIdentities.FindByProviderAndUser(ctx, provider.ID, userId)
	if err != nil {
		return err
	}

	if s.Compare(identity.Credential, old) != nil {
		return ErrPasswordMismatch
	}

	hash, err := s.Digest(new, space.PasswordSettings.BcryptCost)
	if err != nil {
		return err
	}

	identity.Credential = hash

	err = s.UserIdentities.Update(ctx, identity)
	if err != nil {
		return err
	}

	// TODO reset all active sessions

	return nil
}
