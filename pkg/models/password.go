package models

import (
	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
	"unicode"
)

var (
	PasswordBcryptCostDefault     = 8
	PasswordMinDefault            = 4
	PasswordMaxDefault            = 30
	PasswordRequireNumberDefault  = true
	PasswordRequireUpperDefault   = true
	PasswordRequireSpecialDefault = false
	PasswordTokenLengthDefault    = 128
	PasswordTokenTTLDefault       = 3600
)

type PasswordSettings struct {
	ApplicationID  bson.ObjectId `bson:"app_id" json:"application_id"`
	BcryptCost     int           `bson:"bcrypt_cost" json:"bcrypt_cost"`
	Min            int           `bson:"min" json:"min"`
	Max            int           `bson:"max" json:"max"`
	RequireNumber  bool          `bson:"require_number" json:"require_number"`
	RequireUpper   bool          `bson:"require_upper" json:"require_upper"`
	RequireSpecial bool          `bson:"require_special" json:"require_special"`
	TokenLength    int           `bson:"token_length" json:"token_length"`
	TokenTTL       int           `bson:"token_ttl" json:"token_ttl"`
}

func (ps *PasswordSettings) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ApplicationID", ps.ApplicationID.String())
	enc.AddInt("BcryptCost", ps.BcryptCost)
	enc.AddInt("Min", ps.Min)
	enc.AddInt("Max", ps.Max)
	enc.AddBool("RequireNumber", ps.RequireNumber)
	enc.AddBool("RequireUpper", ps.RequireUpper)
	enc.AddBool("RequireSpecial", ps.RequireSpecial)
	enc.AddInt("TokenLength", ps.TokenLength)
	enc.AddInt("TokenTTL", ps.TokenTTL)

	return nil
}

func (ps *PasswordSettings) IsValid(password string) bool {
	letters := 0
	number := false
	upper := false
	special := false

	for _, s := range password {
		switch {
		case unicode.IsNumber(s):
			number = true
		case unicode.IsUpper(s):
			upper = true
			letters++
		case unicode.IsPunct(s) || unicode.IsSymbol(s):
			special = true
		case unicode.IsLetter(s) || s == ' ':
			letters++
		}
	}

	return (ps.RequireNumber == false || ps.RequireNumber == true && number == true) &&
		(ps.RequireUpper == false || ps.RequireUpper == true && upper == true) &&
		(ps.RequireSpecial == false || ps.RequireSpecial == true && special == true) &&
		(len(password) >= ps.Min && len(password) <= ps.Max)
}
