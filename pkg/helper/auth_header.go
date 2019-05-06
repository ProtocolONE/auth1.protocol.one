package helper

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/pkg/errors"
	"net/http"
	"strings"
)

func GetTokenFromAuthHeader(headers http.Header) (token *models.JwtClaim, err error) {
	authHeader := headers.Get(`Authorization`)
	i := strings.Index(authHeader, ` `)
	if -1 == i {
		return nil, errors.New(`invalid authenticate header`)
	}

	s := strings.Split(authHeader, " ")
	if "Bearer" != s[0] {
		return nil, errors.New(`invalid authenticate header name`)
	}
	if "" == s[1] {
		return nil, errors.New(`invalid authenticate header value`)
	}

	clientId := headers.Get("X-CLIENT-ID")
	if "" == clientId {
		return nil, errors.New(`invalid client id`)
	}

	return &models.JwtClaim{}, nil
}
