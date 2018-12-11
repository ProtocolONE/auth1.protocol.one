package helper

import (
	"errors"
	"strings"
)

type AuthHeader struct {
	Token string
}

func GetTokenFromAuthHeader(header string) (token string, err error) {
	i := strings.Index(header, ` `)
	if -1 == i {
		return ``, errors.New(`invalid authenticate header`)
	}

	s := strings.Split(header, ` `)
	if `Bearer` != s[0] {
		return ``, errors.New(`invalid authenticate header name`)
	}
	if `` == s[1] {
		return ``, errors.New(`invalid authenticate header value`)
	}

	return s[1], nil
}
