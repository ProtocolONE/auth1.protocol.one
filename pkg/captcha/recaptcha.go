package captcha

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/juju/zaputil/zapctx"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// Recaptcha provides integration with google recaptcha v3
type Recaptcha struct {
	key      string
	secret   string
	hostname string
}

// NewRecaptcha returns recaptcha integration service with provided key and secret
func NewRecaptcha(key, secret, hostname string) *Recaptcha {
	return &Recaptcha{key, secret, hostname}
}

// Key returns client key
func (r *Recaptcha) Key() string {
	return r.key
}

// Verify checks provided token in recaptcha service
func (r *Recaptcha) Verify(ctx context.Context, token, action, ip string) (bool, error) {
	log := zapctx.Logger(ctx)
	form := url.Values{
		"secret":   {r.secret},
		"response": {token},
	}
	if ip != "" {
		form["remoteip"] = []string{ip}
	}

	// TODO retry
	resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify", form)
	if err != nil {
		return false, errors.WithMessage(err, "recaptcha verify request failed")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, errors.WithMessage(err, "recaptcha verify request failed")
	}

	log.Debug("recaptcha verify", zap.ByteString("response", data))

	var res struct {
		Success     bool     `json:"success"`      //: true,
		ChallengeTs string   `json:"challenge_ts"` //: "2020-02-05T15:26:33Z",
		Hostname    string   `json:"hostname"`     //: "localhost",
		Score       float64  `json:"score"`        //: 0.9,
		Action      string   `json:"action"`       //: "homepage"
		ErrorCodes  []string `json:"error-codes"`
	}

	if err := json.Unmarshal(data, &res); err != nil {
		return false, errors.WithMessage(err, "recaptcha invalid response")
	}

	if !res.Success {
		log.Warn("recaptcha verify errors", zap.Strings("errors", res.ErrorCodes))
		return false, nil
	}

	if action != "" && res.Action != action {
		log.Warn("recaptcha actions doesn't match", zap.String("re_action", res.Action), zap.String("our_action", action))
		return false, nil
	}

	if r.hostname != "" && res.Hostname != r.hostname {
		log.Warn("recaptcha hostname doesn't match", zap.String("re_hostname", res.Hostname), zap.String("our_hostname", r.hostname))
		return false, nil
	}

	if res.Score > 0.5 {
		return true, nil
	}
	return false, nil
}
