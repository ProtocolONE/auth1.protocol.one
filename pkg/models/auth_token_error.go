package models

type AuthTokenError CommonError

func (m AuthTokenError) Error() string {
	return m.Message
}

func (m *AuthTokenError) GetCode() string {
	return m.Code
}

func (m *AuthTokenError) GetMessage() string {
	return m.Message
}
