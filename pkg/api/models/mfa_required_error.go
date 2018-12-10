package models

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
