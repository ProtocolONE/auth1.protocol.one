package models

import "unicode"

type (
	PasswordSettings struct {
		BcryptCost     int
		Min            int
		Max            int
		RequireNumber  bool
		RequireUpper   bool
		RequireSpecial bool
	}
)

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
