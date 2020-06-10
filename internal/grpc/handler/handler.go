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
	profile         service.ProfileService
	Users           repository.UserRepository
	Spaces          repository.SpaceRepository
	userIdentity    service.UserIdentityService
	passwordManager service.PasswordManager
	// app             service.ApplicationService
}

// GET /v1/profile
func (h *Handler) GetProfile(ctx context.Context, r *proto.GetProfileRequest) (*proto.ProfileResponse, error) {
	var w proto.ProfileResponse
	w.UserID = r.UserID

	u, err := h.Users.FindByID(ctx, entity.UserID(r.UserID))
	if err != nil {
		return nil, err
	}
	w.Username = u.Username
	w.Email = u.Email

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
	u, err := h.Users.FindByID(ctx, entity.UserID(r.UserID))
	if err != nil {
		return nil, err
	}

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
			Currency:  r.Currency,
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
			Currency:  r.Currency,
		})
		if err != nil {
			return nil, err
		}
	}

	var w proto.ProfileResponse
	w.Username = u.Username
	w.Email = u.Email

	return &w, fillProfileResponse(&w, p)
}

//
func (h *Handler) GetUserSocialIdentities(ctx context.Context, r *proto.GetUserSocialIdentitiesRequest) (*proto.UserSocialIdentitiesResponse, error) {
	user, err := h.Users.FindByID(ctx, entity.UserID(r.UserID))
	if err != nil {
		return nil, err
	}

	space, err := h.Spaces.FindByID(ctx, user.SpaceID)
	if err != nil {
		return nil, err
	}

	idents, err := h.userIdentity.GetIdentities(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	var resp proto.UserSocialIdentitiesResponse

	for _, id := range idents {
		provider, ok := space.IDProvider(id.IdentityProviderID)
		if !ok {
			continue
		}
		if !provider.IsSocial() {
			continue
		}

		resp.Identities = append(resp.Identities, &proto.UserIdentity{
			Provider:   provider.DisplayName,
			ExternalID: id.ExternalID,
			Email:      id.Email,
			Username:   id.Username,
			Name:       id.Name,
		})

	}

	return &resp, nil
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
	w.Currency = *p.Currency

	return nil
}

func (h *Handler) ChangePassword(ctx context.Context, r *proto.ChangePasswordRequest) (*proto.ChangePasswordResponse, error) {
	if err := h.passwordManager.ChangePassword(ctx,
		entity.UserID(r.UserID),
		r.PasswordOld,
		r.PasswordNew,
	); err != nil {
		return &proto.ChangePasswordResponse{Success: false}, err
	}

	return &proto.ChangePasswordResponse{Success: true}, nil
}
