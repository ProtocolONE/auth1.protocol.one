package validator

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"unicode"
)

// IsPasswordValid verifies the password according to the application password settings criteria.
func IsPasswordValid(app *models.Application, password string) bool {
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

	return (app.PasswordSettings.RequireNumber == false || app.PasswordSettings.RequireNumber == true && number == true) &&
		(app.PasswordSettings.RequireUpper == false || app.PasswordSettings.RequireUpper == true && upper == true) &&
		(app.PasswordSettings.RequireSpecial == false || app.PasswordSettings.RequireSpecial == true && special == true) &&
		(len(password) >= app.PasswordSettings.Min && len(password) <= app.PasswordSettings.Max)
}
