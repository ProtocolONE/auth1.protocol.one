package handler

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/service"
	"github.com/ProtocolONE/auth1.protocol.one/internal/grpc/proto"
	"github.com/ProtocolONE/auth1.protocol.one/internal/service/profile"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
)

type Handler struct {
	profile service.ProfileService
	user    service.UserService
}

// GET /v1/profile
func (h *Handler) GetProfile(ctx context.Context, r *proto.GetProfileRequest, w *proto.ProfileResponse) error {
	p, err := h.profile.GetByUserID(ctx, r.UserID)
	if err != nil {
		return err
	}

	var birthDate *timestamp.Timestamp
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

func (h *Handler) SetProfile(ctx context.Context, r *proto.SetProfileRequest, w *proto.ProfileResponse) error {
	p, err := h.profile.GetByUserID(ctx, r.UserID)
	if err != nil && err != profile.ErrProfileNotFound {
		return err
	}

	birthDate, err := ptypes.Timestamp(r.BirthDate)
	if err != nil {
		return err
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
			return err
		}
	} else {
		p, err = h.profile.Update(ctx, &service.UpdateProfileData{
			ID:        p.ID,
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
			return err
		}
	}

	return nil
}

func (h *Handler) GetSocialProfiles(ctx context.Context, r *proto.GetProfileRequest, w *proto.ProfileResponse) error {
	//
	return nil
}
