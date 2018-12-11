package models

type TemporaryLockedError CommonError

func (m TemporaryLockedError) Error() string {
	return m.Message
}

func (m *TemporaryLockedError) GetCode() string {
	return m.Code
}

func (m *TemporaryLockedError) GetMessage() string {
	return m.Message
}
