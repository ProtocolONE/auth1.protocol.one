package helper

import (
	"auth-one-api/pkg/models"
	"github.com/pkg/errors"
	"net/http"
	"strings"
)

func GetTokenFromAuthHeader(as models.ApplicationService, headers http.Header) (token *models.JwtClaim, err error) {
	authHeader := headers.Get(`Authorization`)
	i := strings.Index(authHeader, ` `)
	if -1 == i {
		return nil, errors.New(`invalid authenticate header`)
	}

	s := strings.Split(authHeader, ` `)
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

	ats, err := as.LoadAuthTokenSettings()
	if err != nil {
		return nil, errors.Wrap(err, "unable to load token settings")
	}

	jts := models.NewJwtTokenService(ats)
	c, err := jts.Decode(s[1])
	if err != nil {
		return nil, errors.Wrap(err, "unable to load jwt settings")
	}

	if err = c.Valid(); err != nil {
		return nil, errors.Wrap(err, "token is invalid")
	}

	return c, nil
}
