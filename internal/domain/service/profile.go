package service

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

type ProfileService interface {
	Create(ctx context.Context, data *CreateProfileData) (*entity.Profile, error)
	Update(ctx context.Context, data *UpdateProfileData) (*entity.Profile, error)
	Delete(ctx context.Context, id string) error

	GetByID(ctx context.Context, id string) (*entity.Profile, error)
	GetByUserID(ctx context.Context, user_id string) (*entity.Profile, error)
}

type CreateProfileData struct {
	UserID string
	//
	Address1 string
	Address2 string
	City     string
	State    string
	Country  string
	Zip      string
	//
	PhotoURL  string
	FirstName string
	LastName  string
	BirthDate uint32
	//
	Language string
}

type UpdateProfileData struct {
	ID     string
	UserId string
	//
	Address1 string
	Address2 string
	City     string
	State    string
	Country  string
	Zip      string
	//
	PhotoURL  string
	FirstName string
	LastName  string
	BirthDate uint32
	//
	Language string
}
