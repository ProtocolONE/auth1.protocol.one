package models

import (
	"time"

	"github.com/globalsign/mgo/bson"
)

// AuthorizeLog describes a table for storing the user authorizations log.
type AuthorizeLog struct {
	// ID is the record id.
	ID bson.ObjectId `bson:"_id" json:"id"`

	// Timestamp in UTC
	Timestamp time.Time `bson:"timestamp" json:"timestamp"`

	// UserID is the user id.
	UserID bson.ObjectId `bson:"user_id" json:"user_id"`

	// ActionType is auth action registration or authentication
	ActionType string `bson:"action_type" json:"action_type"`

	// Referer is browser referer page
	Referer string `bson:"referer" json:"referer"`

	// AppID is application id
	AppID bson.ObjectId `bson:"app_id" json:"app_id"`

	// AppName
	AppName string `bson:"app_name" json:"app_name"`

	// UserAgent is client useragent
	UserAgent string `bson:"useragent" json:"useragent"`

	// IP is user ip
	IP string `bson:"ip" json:"ip"`

	// ClientTime time from http Date header
	ClientTime time.Time `bson:"client_time" json:"client_time"`
}
