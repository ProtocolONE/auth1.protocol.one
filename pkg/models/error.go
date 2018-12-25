package models

type (
	ErrorInterface interface {
		GetCode() string
		GetMessage() string
	}

	CommonError struct {
		Code    string `json:"error,omitempty"`
		Message string `json:"error_message,omitempty"`
	}
)

func (m *CommonError) Error() string {
	return m.Message
}

func (m *CommonError) GetCode() string {
	return m.Code
}

func (m *CommonError) GetMessage() string {
	return m.Message
}
