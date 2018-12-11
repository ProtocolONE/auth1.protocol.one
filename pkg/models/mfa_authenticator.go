package models

type MfaAuthenticator struct {
	Secret        string   `json:"secret"`
	ObbChannel    string   `json:"oob_channel,omitempty"`
	BarcodeUri    string   `json:"barcode_uri,omitempty"`
	Type          string   `json:"authenticator_type"`
	RecoveryCodes []string `json:"recovery_codes"`
}
