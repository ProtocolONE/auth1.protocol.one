package entity

import "unicode"

type PasswordSettings struct {
	// BcryptCost determines the depth of password encryption for providers based on the database.
	// CPU load and performance depend on the BCrypt cost.
	BcryptCost int

	// Min is the minimal length password.
	Min int

	// Max is the maximum length password.
	Max int

	// RequireNumber requires numbers in the password.
	RequireNumber bool

	// RequireUpper requires a capital letter in the password.
	RequireUpper bool

	// RequireSpecial requires special characters in the password (~,!, @, and the like).
	RequireSpecial bool

	// RequireLetter requires a letter in the password.
	RequireLetter bool

	// TokenLength determines the length of the token in the password change letter.
	TokenLength int

	// TokenTTL determines the token's lifetime in the password change letter.
	TokenTTL int
}

var DefaultPasswordSettings = PasswordSettings{
	BcryptCost:     8,
	Min:            7,
	Max:            30,
	RequireNumber:  true,
	RequireUpper:   false,
	RequireSpecial: false,
	RequireLetter:  true,
	TokenLength:    128,
	TokenTTL:       3600,
}

func (s *PasswordSettings) IsValid(password string) bool {
	letters := 0
	number := false
	upper := false
	special := false

	for _, c := range password {
		switch {
		case unicode.IsNumber(c):
			number = true
		case unicode.IsUpper(c):
			upper = true
			letters++
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			special = true
		case unicode.IsLetter(c) || c == ' ':
			letters++
		}
	}

	if s.RequireNumber && !number {
		return false
	}
	if s.RequireUpper && !upper {
		return false
	}
	if s.RequireSpecial && !special {
		return false
	}
	if s.RequireLetter && letters == 0 {
		return false
	}
	return s.Min <= len(password) && len(password) <= s.Max
}
