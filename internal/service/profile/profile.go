package profile

import (
	"context"
	"errors"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/service"
)

type Service struct {
	ServiceParams
}

var ErrProfileNotFound = errors.New("profile not found")

func (s Service) Create(ctx context.Context, data *service.CreateProfileData) (*entity.Profile, error) {
	profile := &entity.Profile{
		UserID:    data.UserID,
		Address1:  &data.Address1,
		Address2:  &data.Address2,
		City:      &data.City,
		State:     &data.State,
		Country:   &data.Country,
		Zip:       &data.Zip,
		PhotoURL:  &data.PhotoURL,
		FirstName: &data.FirstName,
		LastName:  &data.LastName,
		BirthDate: &data.BirthDate,
		Language:  &data.Language,
	}
	if err := s.ProfileRepo.Create(ctx, profile); err != nil {
		return nil, err
	}

	return profile, nil
}

func (s Service) Update(ctx context.Context, data *service.UpdateProfileData) (*entity.Profile, error) {
	profile, err := s.GetByUserID(ctx, data.UserId)
	if err != nil {
		return nil, err
	}

	profile.UserID = data.UserId
	profile.Address1 = &data.Address1
	profile.Address2 = &data.Address2
	profile.City = &data.City
	profile.State = &data.State
	profile.Country = &data.Country
	profile.Zip = &data.Zip
	profile.PhotoURL = &data.PhotoURL
	profile.FirstName = &data.FirstName
	profile.LastName = &data.LastName
	profile.BirthDate = &data.BirthDate
	profile.Language = &data.Language

	if err == ErrProfileNotFound {
		err = s.ProfileRepo.Create(ctx, profile)
		if err != nil {
			return nil, err
		}
		return profile, nil
	}

	err = s.ProfileRepo.Update(ctx, profile)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

func (s Service) Delete(ctx context.Context, id string) error {
	panic("not implemented") // TODO
}

func (s Service) GetByID(ctx context.Context, id string) (*entity.Profile, error) {
	profile, err := s.ProfileRepo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, ErrProfileNotFound
	}
	return profile, nil
}

func (s Service) GetByUserID(ctx context.Context, user_id string) (*entity.Profile, error) {
	profile, err := s.ProfileRepo.FindByUserID(ctx, user_id)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, ErrProfileNotFound
	}
	return profile, nil
}
