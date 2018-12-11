package models

type CaptchaRequiredError CommonError

func (m CaptchaRequiredError) Error() string {
	return m.Message
}

func (m *CaptchaRequiredError) GetCode() string {
	return m.Code
}

func (m *CaptchaRequiredError) GetMessage() string {
	return m.Message
}
