package models

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
)

type AuthToken struct {
	AccessToken  string `json:"access_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"id_token,omitempty"`
}

type OneTimeTokenSettings struct {
	Length int
	TTL    int
}

type OneTimeToken struct {
	Token string `json:"token,omitempty"`
}

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
