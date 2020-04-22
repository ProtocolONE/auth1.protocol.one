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

func (s Service) GetByID(ctx context.Context, id string) (*entity.UserIdentity, error) {
	ui, err := s.UserIdentityRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if ui == nil {
		return nil, ErrUserIdentityNotFound
	}
	return ui, nil
}

func (s Service) UpdateCredential(ctx context.Context, data *service.UpdateUserIdentityCredentialData) error {
	ui, err := s.UserIdentityRepo.GetByID(ctx, data.ID)
	if err != nil {
		return err
	}
	if ui == nil {
		return ErrUserIdentityNotFound
	}
	ui.Credential = data.Credential
	return s.UserIdentityRepo.Update(ctx, ui)
}

func (s Service) GetIdentity(ctx context.Context, data *service.GetIdentityData) (*entity.UserIdentity, error) {
	ui, err := s.UserIdentityRepo.FindIdentity(ctx, data.AppID, data.IdentityProviderID, data.UserID)
	if err != nil {
		return nil, err
	}
	if ui == nil {
		return nil, ErrUserIdentityNotFound
	}
	return ui, nil
}

func (s Service) GetIdentities(ctx context.Context, appID, userID string) ([]*entity.UserIdentity, error) {
	ids, err := s.UserIdentityRepo.FindIdentities(ctx, appID, userID)
	if err != nil {
		return nil, err
	}
	return ids, nil
}
