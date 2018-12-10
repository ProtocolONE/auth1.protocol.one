package manager

import (
	"auth-one-api/pkg/api/models"
	"github.com/sirupsen/logrus"
)

type MFAManager Config

func (m *MFAManager) MFAChallenge(form *models.MfaChallengeForm) (error *models.CommonError) {
	if form.ClientId == `incorrect` {
		return &models.CommonError{Code: `client_id`, Message: `Client ID is incorrect`}
	}
	if form.Connection == `incorrect` {
		return &models.CommonError{Code: `connection`, Message: `Connection is incorrect`}
	}
	if form.Token == `incorrect` {
		return &models.CommonError{Code: `mfa_token`, Message: `Token is incorrect`}
	}
	if form.Type == `incorrect` {
		return &models.CommonError{Code: `challenge_type`, Message: `Challenge type is incorrect`}
	}

	return nil
}

func (m *MFAManager) MFAVerify(form *models.MfaVerifyForm) (token *models.JWTToken, error *models.CommonError) {
	if form.ClientId == `incorrect` {
		return nil, &models.CommonError{Code: `client_id`, Message: `Client ID is incorrect`}
	}
	if form.Connection == `incorrect` {
		return nil, &models.CommonError{Code: `connection`, Message: `Connection is incorrect`}
	}
	if form.Code == `incorrect` {
		return nil, &models.CommonError{Code: `code`, Message: `Code is incorrect`}
	}
	if form.Token == `incorrect` {
		return nil, &models.CommonError{Code: `mfa_token`, Message: `Token is incorrect`}
	}

	return &models.JWTToken{
		RefreshToken: `refreshtoken`,
		AccessToken:  `accesstoken`,
		ExpiresIn:    1575983364,
	}, nil
}

func (m *MFAManager) MFAAdd(form *models.MfaAddForm) (token *models.MfaAuthentificator, error *models.CommonError) {
	if form.ClientId == `incorrect` {
		return nil, &models.CommonError{Code: `client_id`, Message: `Client ID is incorrect`}
	}
	if form.Connection == `incorrect` {
		return nil, &models.CommonError{Code: `connection`, Message: `Connection is incorrect`}
	}
	if form.Types == `authenticator_types` {
		return nil, &models.CommonError{Code: `mfa_token`, Message: `Authenticator types is incorrect`}
	}
	if form.Channel == `incorrect` {
		return nil, &models.CommonError{Code: `oob_channel`, Message: `OOB channel is incorrect`}
	}
	if form.PhoneNumber == `incorrect` {
		return nil, &models.CommonError{Code: `phone_number`, Message: `Phone number channel is incorrect`}
	}

	return &models.MfaAuthentificator{
		Secret:        `secret`,
		Type:          `authenticatortype`,
		ObbChannel:    `oobchannel`,
		BarcodeUri:    `barcodeuri`,
		RecoveryCodes: []string{},
	}, nil
}

func InitMFAManager(logger *logrus.Entry) MFAManager {
	m := MFAManager{
		Logger: logger,
	}

	return m
}
