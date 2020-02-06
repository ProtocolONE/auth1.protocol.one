package api

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/labstack/echo/v4"
)

func InitCaptcha(cfg *Server) error {
	g := cfg.Echo.Group("/captcha", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := c.Get("database").(database.MgoSession)
			c.Set("mfa_manager", manager.NewMFAManager(db, cfg.Registry))

			return next(c)
		}
	})

	g.POST("/re3", captchaVerify)

	return nil
}

func captchaVerify(ctx echo.Context) error {
	var r struct {
		Token string `json:"token"`
	}
	// m := ctx.Get("mfa_manager").(*manager.MFAManager)

	if err := ctx.Bind(&r); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
		}
		ctx.Error(err)
		return ctx.JSON(http.StatusBadRequest, e)
	}

	result, err := verifyRecaptcha3(r.Token)
	if err != nil {
		ctx.Error(err)
		return ctx.JSON(http.StatusInternalServerError, &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
		})
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"success": result,
	})
}

func verifyRecaptcha3(token string) (bool, error) {
	resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify", url.Values{
		"secret":   {"6Lea_dUUAAAAAK294XwQmOIujxW8ssNRk_zWU5AB"},
		"response": {token},
		// "remoteip"
	})
	if err != nil {
		return false, err
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var res struct {
		Success     bool     `json:"success"`      //: true,
		ChallengeTs string   `json:"challenge_ts"` //: "2020-02-05T15:26:33Z",
		Hostname    string   `json:"hostname"`     //: "localhost",
		Score       float64  `json:"score"`        //: 0.9,
		Action      string   `json:"action"`       //: "homepage"
		ErrorCodes  []string `json:"error_codes"`
	}

	if err := json.Unmarshal(data, &res); err != nil {
		return false, err
	}

	if res.Success && res.Score > 0.5 {
		return true, nil
	}
	return false, nil
}
