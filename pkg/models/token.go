package models

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
)

// OneTimeTokenSettings contains settings for to generate one-time token.
type OneTimeTokenSettings struct {
	// Length is the length of token.
	Length int `bson:"length" json:"length"`

	//TTL is the expiration time for the token.
	TTL int `bson:"ttl" json:"ttl"`
}

// OneTimeToken contains one-time token.
type OneTimeToken struct {
	// Token is the value of one-time token.
	Token string `json:"token,omitempty"`
}

// LauncherTokenSettings contains settings for stored launcher token.
type LauncherTokenSettings struct {
	//TTL is the expiration time for the token.
	TTL int `bson:"ttl" json:"ttl"`
}

type LauncherToken struct {
	// Name is the name of social provider
	Name string `json:"name"`
	// Status stores state of the login process
	Status string `json:"status"`
}

// JwtClaim is deprecated and will be removed.
type JwtClaim struct {
	UserId         bson.ObjectId `json:"user_id"`
	AppId          bson.ObjectId `json:"app_id"`
	Email          string        `json:"email"`
	EmailConfirmed bool          `json:"email_confirmed"`
	Nickname       string        `json:"nickname"`
	jwt.StandardClaims
}

func (a *OneTimeToken) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Token", a.Token)

	return nil
}
