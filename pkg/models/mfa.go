package models

type MfaAuthenticator struct {
	Secret        string   `json:"secret"`
	ObbChannel    string   `json:"oob_channel,omitempty"`
	BarcodeUri    string   `json:"barcode_uri,omitempty"`
	Type          string   `json:"authenticator_type"`
	RecoveryCodes []string `json:"recovery_codes"`
}

type MfaChallengeForm struct {
	ClientId   string `json:"client_id" form:"client_id" validate:"required"`
	Connection string `json:"connection" form:"connection" validate:"required"`
	Token      string `json:"mfa_token" form:"mfa_token" validate:"required"`
	Type       string `json:"challenge_type" form:"challenge_type"`
}

type MfaVerifyForm struct {
	ClientId   string `json:"client_id" form:"client_id" validate:"required"`
	Connection string `json:"connection" form:"connection" validate:"required"`
	Token      string `json:"mfa_token" form:"mfa_token" validate:"required"`
	Code       string `json:"code" form:"code"`
}

type MfaAddForm struct {
	ClientId    string `json:"client_id" form:"client_id" validate:"required"`
	Connection  string `json:"connection" form:"connection" validate:"required"`
	Types       string `json:"authenticator_types" form:"authenticator_types" validate:"required"`
	Channel     string `json:"oob_channel" form:"oob_channel"`
	PhoneNumber string `json:"phone_number" form:"phone_number"`
}

type MFARequiredError CommonError

func (m MFARequiredError) Error() string {
	return m.Message
}

func (m *MFARequiredError) GetCode() string {
	return m.Code
}

func (m *MFARequiredError) GetMessage() string {
	return m.Message
}
