// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import admin "github.com/ory/hydra-client-go/client/admin"
import mock "github.com/stretchr/testify/mock"
import runtime "github.com/go-openapi/runtime"

// HydraAdminApi is an autogenerated mock type for the HydraAdminApi type
type HydraAdminApi struct {
	mock.Mock
}

// AcceptConsentRequest provides a mock function with given fields: _a0
func (_m *HydraAdminApi) AcceptConsentRequest(_a0 *admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error) {
	ret := _m.Called(_a0)

	var r0 *admin.AcceptConsentRequestOK
	if rf, ok := ret.Get(0).(func(*admin.AcceptConsentRequestParams) *admin.AcceptConsentRequestOK); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*admin.AcceptConsentRequestOK)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*admin.AcceptConsentRequestParams) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AcceptLoginRequest provides a mock function with given fields: _a0
func (_m *HydraAdminApi) AcceptLoginRequest(_a0 *admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
	ret := _m.Called(_a0)

	var r0 *admin.AcceptLoginRequestOK
	if rf, ok := ret.Get(0).(func(*admin.AcceptLoginRequestParams) *admin.AcceptLoginRequestOK); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*admin.AcceptLoginRequestOK)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*admin.AcceptLoginRequestParams) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateOAuth2Client provides a mock function with given fields: _a0
func (_m *HydraAdminApi) CreateOAuth2Client(_a0 *admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
	ret := _m.Called(_a0)

	var r0 *admin.CreateOAuth2ClientCreated
	if rf, ok := ret.Get(0).(func(*admin.CreateOAuth2ClientParams) *admin.CreateOAuth2ClientCreated); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*admin.CreateOAuth2ClientCreated)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*admin.CreateOAuth2ClientParams) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetConsentRequest provides a mock function with given fields: _a0
func (_m *HydraAdminApi) GetConsentRequest(_a0 *admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
	ret := _m.Called(_a0)

	var r0 *admin.GetConsentRequestOK
	if rf, ok := ret.Get(0).(func(*admin.GetConsentRequestParams) *admin.GetConsentRequestOK); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*admin.GetConsentRequestOK)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*admin.GetConsentRequestParams) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetLoginRequest provides a mock function with given fields: _a0
func (_m *HydraAdminApi) GetLoginRequest(_a0 *admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
	ret := _m.Called(_a0)

	var r0 *admin.GetLoginRequestOK
	if rf, ok := ret.Get(0).(func(*admin.GetLoginRequestParams) *admin.GetLoginRequestOK); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*admin.GetLoginRequestOK)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*admin.GetLoginRequestParams) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetOAuth2Client provides a mock function with given fields: _a0
func (_m *HydraAdminApi) GetOAuth2Client(_a0 *admin.GetOAuth2ClientParams) (*admin.GetOAuth2ClientOK, error) {
	ret := _m.Called(_a0)

	var r0 *admin.GetOAuth2ClientOK
	if rf, ok := ret.Get(0).(func(*admin.GetOAuth2ClientParams) *admin.GetOAuth2ClientOK); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*admin.GetOAuth2ClientOK)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*admin.GetOAuth2ClientParams) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IntrospectOAuth2Token provides a mock function with given fields: _a0, _a1
func (_m *HydraAdminApi) IntrospectOAuth2Token(_a0 *admin.IntrospectOAuth2TokenParams, _a1 runtime.ClientAuthInfoWriter) (*admin.IntrospectOAuth2TokenOK, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *admin.IntrospectOAuth2TokenOK
	if rf, ok := ret.Get(0).(func(*admin.IntrospectOAuth2TokenParams, runtime.ClientAuthInfoWriter) *admin.IntrospectOAuth2TokenOK); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*admin.IntrospectOAuth2TokenOK)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*admin.IntrospectOAuth2TokenParams, runtime.ClientAuthInfoWriter) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateOAuth2Client provides a mock function with given fields: _a0
func (_m *HydraAdminApi) UpdateOAuth2Client(_a0 *admin.UpdateOAuth2ClientParams) (*admin.UpdateOAuth2ClientOK, error) {
	ret := _m.Called(_a0)

	var r0 *admin.UpdateOAuth2ClientOK
	if rf, ok := ret.Get(0).(func(*admin.UpdateOAuth2ClientParams) *admin.UpdateOAuth2ClientOK); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*admin.UpdateOAuth2ClientOK)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*admin.UpdateOAuth2ClientParams) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
