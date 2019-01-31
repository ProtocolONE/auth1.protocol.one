package helper

import (
	"auth-one-api/pkg/models"
	"net/http"
)

func PrepareRedirectUrl(url string, token *models.OneTimeToken) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	q := req.URL.Query()
	q.Add("auth_one_ott", token.Token)
	req.URL.RawQuery = q.Encode()

	return req.URL.String(), nil
}
