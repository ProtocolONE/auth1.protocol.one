package models

import (
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"time"
)

type (
	IdentityProviderService struct {
		db *mgo.Database
	}

	Connection struct {
		ID       bson.ObjectId `bson:"_id" json:"id"`
		Name     string        `bson:"name" json:"name"`
		Slug     string        `bson:"slug" json:"slug"`
		IsSocial bool          `bson:"is_social" json:"is_social"`

		ClientID         string    `bson:"client_id" json:"client_id"`
		ClientSecret     string    `bson:"client_secret" json:"client_secret"`
		Scopes           []string  `bson:"scopes" json:"scopes"`
		AvailableDomains []string  `bson:"available_domains" json:"available_domains"`
		CreatedAt        time.Time `bson:"created_at" json:"created_at"`
		UpdatedAt        time.Time `bson:"updated_at" json:"updated_at"`
	}

	IdentityProvider struct {
		ID               bson.ObjectId `bson:"_id" json:"id"`
		ApplicationID    bson.ObjectId `bson:"app_id" json:"app_id"`
		ConnectionID     string        `bson:"connection_id" json:"connection_id"`
		ClientID         string        `bson:"client_id" json:"client_id"`
		ClientSecret     string        `bson:"client_secret" json:"client_secret"`
		Scopes           []string      `bson:"scopes" json:"scopes"`
		AvailableDomains []string      `bson:"available_domains" json:"available_domains"`
		CreatedAt        time.Time     `bson:"created_at" json:"created_at"`
		UpdatedAt        time.Time     `bson:"updated_at" json:"updated_at"`
	}
)
