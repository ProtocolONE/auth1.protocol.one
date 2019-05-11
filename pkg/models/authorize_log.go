package models

import (
	"github.com/globalsign/mgo/bson"
)

// AuthorizeLog describes a table for storing the user authorizations log.
type AuthorizeLog struct {
	// ID is the record id.
	ID bson.ObjectId `bson:"_id" json:"id"`

	// UserID is the user id.
	UserID bson.ObjectId `bson:"user_id" json:"user_id"`

	// UserAgentId is the user agent id.
	UserAgentId bson.ObjectId `bson:"useragent_id" json:"useragent_id"`

	// IpId is the ip id.
	IpId bson.ObjectId `bson:"ip_id" json:"ip_id"`
}

// AuthorizeLog describes a table for storing the user authorizations agents.
type AuthorizeUserAgent struct {
	// ID is the record id.
	ID bson.ObjectId `bson:"_id" json:"id"`

	// Value is the user agent.
	Value string `bson:"value" json:"value"`
}

// AuthorizeLog describes a table for storing the user authorizations ips.
type AuthorizeUserIP struct {
	// ID is the record id.
	ID bson.ObjectId `bson:"_id" json:"id"`

	// Value is the ip address.
	Value string `bson:"value" json:"value"`
}
