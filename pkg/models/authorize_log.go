package models

import (
	"github.com/globalsign/mgo/bson"
)

type (
	AuthorizeLog struct {
		ID          bson.ObjectId `bson:"_id" json:"id"`
		UserID      bson.ObjectId `bson:"user_id" json:"user_id"`
		Token       string        `bson:"token" json:"token"`
		UserAgentId bson.ObjectId `bson:"useragent_id" json:"useragent_id"`
		IpId        bson.ObjectId `bson:"ip_id" json:"ip_id"`
	}

	AuthorizeUserAgent struct {
		ID    bson.ObjectId `bson:"_id" json:"id"`
		Value string        `bson:"value" json:"value"`
	}

	AuthorizeUserIP struct {
		ID    bson.ObjectId `bson:"_id" json:"id"`
		Value string        `bson:"value" json:"value"`
	}
)
