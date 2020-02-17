package apierror

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/assert"
)

func TestHandleNotFoundError(t *testing.T) {
	// Arrange
	var errorJSON = `{"code":"AU-1014","error":"errors.one.protocol.auth1.not_found"}
`
	e, rec := echo.New(), httptest.NewRecorder()
	e.HTTPErrorHandler = Handler
	c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)

	// Act
	c.Error(echo.ErrNotFound)

	// Assert
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, errorJSON, rec.Body.String())
}

func TestHandleNotAllowedError(t *testing.T) {
	// Arrange
	var errorJSON = `{"code":"AU-1013","error":"errors.one.protocol.auth1.method_not_allowed"}
`
	e, rec := echo.New(), httptest.NewRecorder()
	e.HTTPErrorHandler = Handler
	c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)

	// Act
	c.Error(echo.ErrMethodNotAllowed)

	// Assert
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Equal(t, errorJSON, rec.Body.String())
}

func TestHandleUnknownError(t *testing.T) {
	// Arrange
	var unkErrorJSON = `{"code":"AU-1000","error":"errors.one.protocol.auth1.unknown"}
`
	e, rec := echo.New(), httptest.NewRecorder()
	e.HTTPErrorHandler = Handler
	c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)

	// Act
	c.Error(errors.New("some new error"))

	// Assert
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, unkErrorJSON, rec.Body.String())
}

func TestHandleAPIError(t *testing.T) {
	// Arrange
	var testErrorJSON = `{"code":"AU-100","error":"errors.one.protocol.auth1.test"}
`
	e, rec := echo.New(), httptest.NewRecorder()
	e.HTTPErrorHandler = Handler
	c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)

	// Act
	c.Error(New(100, "test", http.StatusTeapot))

	// Assert
	assert.Equal(t, http.StatusTeapot, rec.Code)
	assert.Equal(t, testErrorJSON, rec.Body.String())
}

func TestHandleAPIErrorWithParam(t *testing.T) {
	// Arrange
	var testErrorJSON = `{"code":"AU-100","error":"errors.one.protocol.auth1.test","param":"some"}
`
	e, rec := echo.New(), httptest.NewRecorder()
	e.HTTPErrorHandler = Handler
	c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)

	// Act
	c.Error(New(100, "test", http.StatusTeapot).WithParam("some"))

	// Assert
	assert.Equal(t, http.StatusTeapot, rec.Code)
	assert.Equal(t, testErrorJSON, rec.Body.String())
}

func TestHandleErrorWithRequestID(t *testing.T) {
	// Arrange
	var testErrorJSON = `{"code":"AU-100","error":"errors.one.protocol.auth1.test","request_id":"request-id"}
`
	e, rec := echo.New(), httptest.NewRecorder()
	e.HTTPErrorHandler = Handler
	// e.Use(middleware.RequestID())
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Add(echo.HeaderXRequestID, "request-id")
	c := e.NewContext(req, rec)

	// Act
	middleware.RequestID()(echo.NotFoundHandler)(c) // apply middleware
	c.Error(New(100, "test", http.StatusTeapot))

	// Assert
	assert.Equal(t, http.StatusTeapot, rec.Code)
	assert.Equal(t, testErrorJSON, rec.Body.String())
}

func TestHandleErrorMethodHEAD(t *testing.T) {
	// Arrange
	e, rec := echo.New(), httptest.NewRecorder()
	e.HTTPErrorHandler = Handler
	c := e.NewContext(httptest.NewRequest(http.MethodHead, "/", nil), rec)

	// Act
	c.Error(New(100, "test", http.StatusTeapot))

	// Assert
	assert.Equal(t, http.StatusTeapot, rec.Code)
	assert.Equal(t, "", rec.Body.String())
}
