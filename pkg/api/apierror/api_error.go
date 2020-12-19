package apierror

type APIError struct {
	Code    string      `json:"code"`
	Message string      `json:"error"`
	Status  int         `json:"-"`
	Param   string      `json:"param,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

var _ error = &APIError{} // assert error interface

func NewAPIError(code string, message string, status int) *APIError {
	return &APIError{
		Message: message,
		Code:    code,
		Status:  status,
	}
}

func (e *APIError) Error() string { return e.Code + " " + e.Message }

func (e *APIError) WithParam(param string) *APIError {
	var c = *e
	c.Param = param
	return &c
}

func (e *APIError) WithData(data interface{}) *APIError {
	var c = *e
	c.Data = data
	return &c
}
