package models

type MFARequest struct {
	AuthenticatorType string   `json:"authenticator_type,omitempty"`
	BarcodeURI        string   `json:"barcode_uri,omitempty"`
	OobChannel        string   `json:"oob_channel,omitempty"`
	RecoveryCodes     []string `json:"recovery_codes"`
	Secret            string   `json:"secret,omitempty"`
}
