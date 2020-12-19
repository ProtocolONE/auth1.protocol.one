package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/api/apierror"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestInvalidCSRFError(t *testing.T) {
	// Arrange
	var errorJSON = `{"code":"AU-1012","error":"errors.one.protocol.auth1.invalid_csrf_token","param":"x-xsrf-token"}
`
	e, rec := echo.New(), httptest.NewRecorder()
	e.HTTPErrorHandler = apierror.Handler
	e.Use(CSRFWithConfig(CSRFConfig{
		TokenLookup: "header:X-XSRF-TOKEN",
		CookieName:  "_csrf",
	}))

	// Act
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))

	// Assert
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, errorJSON, rec.Body.String())
}

func TestCSRFVerification(t *testing.T) {
	// Arrange
	e, rec := echo.New(), httptest.NewRecorder()
	e.HTTPErrorHandler = apierror.Handler
	e.Use(CSRFWithConfig(CSRFConfig{
		TokenLookup: "header:X-XSRF-TOKEN",
		CookieName:  "_csrf",
	}))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Add("x-xsrf-token", "0e8ff3c4-9f1c-4882-a105-086167fad6ff")
	req.AddCookie(&http.Cookie{
		Name:  "_csrf",
		Value: "0e8ff3c4-9f1c-4882-a105-086167fad6ff",
	})

	// Act
	e.ServeHTTP(rec, req)

	// Assert
	assert.Equal(t, http.StatusNotFound, rec.Code)
}
