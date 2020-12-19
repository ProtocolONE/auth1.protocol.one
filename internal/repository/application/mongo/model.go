package mongo

import (
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/globalsign/mgo/bson"
)

type model struct {
	// ID is the id for application
	ID bson.ObjectId `bson:"_id" json:"id"`

	// SpaceId is the identifier of the space to which the application belongs.
	SpaceID bson.ObjectId `bson:"space_id" json:"space_id"`

	// Name is the human-readable string name of the application to be presented to the end-user during authorization.
	Name string `bson:"name" json:"name" validate:"required"`

	// Description is the human-readable string description of the application and not be presented to the users.
	Description string `bson:"description" json:"description"`

	// IsActive allows you to enable or disable the application for authorization.
	IsActive bool `bson:"is_active" json:"is_active"`

	// CreatedAt returns the timestamp of the application creation.
	CreatedAt time.Time `bson:"created_at" json:"-"`

	// UpdatedAt returns the timestamp of the last update.
	UpdatedAt time.Time `bson:"updated_at" json:"-"`

	// AuthSecret is a secret string with which the application checks the authentication code and
	// exchanges it for an access token.
	AuthSecret string `bson:"auth_secret" json:"auth_secret" validate:"required"`

	// AuthRedirectUrls is an array of allowed redirect urls for the client.
	AuthRedirectUrls []string `bson:"auth_redirect_urls" json:"auth_redirect_urls" validate:"required"`

	// PostLogoutRedirectUris is an array of allowed post logout redirect urls for the client.
	PostLogoutRedirectUrls []string `bson:"post_logout_redirect_urls" json:"post_logout_redirect_urls"`

	// WebHook endpoint URLs
	WebHooks []string `bson:"webhooks" json:"webhooks"`
}

func (m model) Convert() *entity.Application {
	return &entity.Application{
		ID:                     entity.AppID(m.ID.Hex()),
		SpaceID:                entity.SpaceID(m.SpaceID.Hex()),
		Name:                   m.Name,
		Description:            m.Description,
		IsActive:               m.IsActive,
		CreatedAt:              m.CreatedAt,
		UpdatedAt:              m.UpdatedAt,
		AuthSecret:             m.AuthSecret,
		AuthRedirectUrls:       m.AuthRedirectUrls,
		PostLogoutRedirectUrls: m.PostLogoutRedirectUrls,
		WebHooks:               m.WebHooks,
	}
}
