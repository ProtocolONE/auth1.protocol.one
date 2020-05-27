package handler

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/service"
	"github.com/ProtocolONE/auth1.protocol.one/internal/grpc/proto"
	"github.com/ProtocolONE/auth1.protocol.one/internal/service/profile"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
)

type Handler struct {
	profile      service.ProfileService
	user         service.UserService
	userIdentity service.UserIdentityService
	userPassword service.UserPasswordService
	app          service.ApplicationService
}

// GET /v1/profile
func (h *Handler) GetProfile(ctx context.Context, r *proto.GetProfileRequest) (*proto.ProfileResponse, error) {
	var w proto.ProfileResponse
	w.UserID = r.UserID
	p, err := h.profile.GetByUserID(ctx, r.UserID)
	if err == profile.ErrProfileNotFound {
		return &w, nil
	}
	if err != nil {
		return nil, err
	}

	return &w, fillProfileResponse(&w, p)
}

func (h *Handler) SetProfile(ctx context.Context, r *proto.SetProfileRequest) (*proto.ProfileResponse, error) {
	p, err := h.profile.GetByUserID(ctx, r.UserID)
	if err != nil && err != profile.ErrProfileNotFound {
		return nil, err
	}

	birthDate, err := ptypes.Timestamp(r.BirthDate)
	if err != nil {
		return nil, err
	}

	if err == profile.ErrProfileNotFound {
		p, err = h.profile.Create(ctx, &service.CreateProfileData{
			UserID:    r.UserID,
			Address1:  r.Address1,
			Address2:  r.Address2,
			City:      r.City,
			State:     r.State,
			Country:   r.Country,
			Zip:       r.Zip,
			PhotoURL:  r.PhotoURL,
			FirstName: r.FirstName,
			LastName:  r.LastName,
			BirthDate: birthDate,
			Language:  r.Language,
		})
		if err != nil {
			return nil, err
		}
	} else {
		p, err = h.profile.Update(ctx, &service.UpdateProfileData{
			UserId:    r.UserID,
			Address1:  r.Address1,
			Address2:  r.Address2,
			City:      r.City,
			State:     r.State,
			Country:   r.Country,
			Zip:       r.Zip,
			PhotoURL:  r.PhotoURL,
			FirstName: r.FirstName,
			LastName:  r.LastName,
			BirthDate: birthDate,
			Language:  r.Language,
		})
		if err != nil {
			return nil, err
		}
	}

	var w proto.ProfileResponse
	return &w, fillProfileResponse(&w, p)
}

func (h *Handler) SetPassword(ctx context.Context, r *proto.SetPasswordRequest) (*proto.SetPasswordResponse, error) {
	var w proto.SetPasswordResponse
	if err := h.userPassword.SetPassword(ctx, service.SetPasswordData{
		AppID:       r.AppID,
		UserID:      r.UserID,
		PasswordOld: r.PasswordOld,
		PasswordNew: r.PasswordNew,
	}); err != nil {
		w.AppID = r.AppID
		w.UserID = r.UserID
		w.Success = false
		return &w, err
	}

	w.AppID = r.AppID
	w.UserID = r.UserID
	w.Success = true
	return &w, nil
}

//
func (h *Handler) GetUserSocialIdentities(ctx context.Context, r *proto.GetUserSocialIdentitiesRequest) (*proto.UserSocialIdentitiesResponse, error) {
	var w proto.UserSocialIdentitiesResponse
	app, err := h.app.GetByID(ctx, r.AppID)
	if err != nil {
		return nil, err
	}

	providers := map[string]*entity.IdentityProvider{}
	for _, provider := range app.IdentityProviders {
		providers[provider.ID] = provider
	}

	ids, err := h.userIdentity.GetIdentities(ctx, r.AppID, r.UserID)
	if err != nil {
		return nil, err
	}

	for _, id := range ids {
		provider, ok := providers[id.IdentityProviderID]
		if !ok {
			continue
		}

		if provider.Type != repository.UserIdentity_Social {
			continue
		}

		var (
			email    string
			username string
			name     string
		)

		if id.Email != nil {
			email = *id.Email
		}
		if id.Username != nil {
			username = *id.Username
		}
		if id.Name != nil {
			name = *id.Name
		}

		w.Identities = append(w.Identities, &proto.UserIdentity{
			Provider:   provider.DisplayName,
			ExternalID: id.ExternalID,
			Email:      email,
			Username:   username,
			Name:       name,
		})
	}

	return &w, nil
}

func fillProfileResponse(w *proto.ProfileResponse, p *entity.Profile) error {
	var (
		birthDate *timestamp.Timestamp
		err       error
	)
	if p.BirthDate != nil {
		birthDate, err = ptypes.TimestampProto(*p.BirthDate)
		if err != nil {
			return err
		}
	}

	w.UserID = p.UserID
	//
	w.Address1 = *p.Address1
	w.Address2 = *p.Address2
	w.City = *p.City
	w.State = *p.State
	w.Country = *p.Country
	w.Zip = *p.Zip
	//
	w.PhotoURL = *p.PhotoURL
	w.FirstName = *p.FirstName
	w.LastName = *p.LastName
	w.BirthDate = birthDate
	//
	w.Language = *p.Language

	return nil
}
