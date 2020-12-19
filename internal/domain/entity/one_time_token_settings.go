package entity

type OneTimeTokenSettings struct {
	// Length is the length of token.
	Length int

	//TTL is the expiration time for the token.
	TTL int
}
