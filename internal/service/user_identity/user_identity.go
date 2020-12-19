package user_identity

import (
	"context"
	"errors"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/service"
)

type Service struct {
	ServiceParams
}

var ErrUserIdentityNotFound = errors.New("user identity not found")

func (s Service) GetByID(ctx context.Context, id entity.UserIdentityID) (*entity.UserIdentity, error) {
	ui, err := s.UserIdentityRepo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if ui == nil {
		return nil, ErrUserIdentityNotFound
	}
	return ui, nil
}

func (s Service) UpdateCredential(ctx context.Context, data *service.UpdateUserIdentityCredentialData) error {
	ui, err := s.UserIdentityRepo.FindByID(ctx, entity.UserIdentityID(data.ID))
	if err != nil {
		return err
	}
	if ui == nil {
		return ErrUserIdentityNotFound
	}
	ui.Credential = data.Credential
	return s.UserIdentityRepo.Update(ctx, ui)
}

func (s Service) GetIdentity(ctx context.Context, pid entity.IdentityProviderID, uid entity.UserID) (*entity.UserIdentity, error) {
	ui, err := s.UserIdentityRepo.FindByProviderAndUser(ctx, pid, uid)
	if err != nil {
		return nil, err
	}
	if ui == nil {
		return nil, ErrUserIdentityNotFound
	}
	return ui, nil
}

func (s Service) GetIdentities(ctx context.Context, userID entity.UserID) ([]*entity.UserIdentity, error) {
	ids, err := s.UserIdentityRepo.FindForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return ids, nil
}
