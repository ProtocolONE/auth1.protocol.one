// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"
import models "github.com/ProtocolONE/auth1.protocol.one/pkg/models"

// OneTimeTokenServiceInterface is an autogenerated mock type for the OneTimeTokenServiceInterface type
type OneTimeTokenServiceInterface struct {
	mock.Mock
}

// Create provides a mock function with given fields: obj, settings
func (_m *OneTimeTokenServiceInterface) Create(obj interface{}, settings *models.OneTimeTokenSettings) (*models.OneTimeToken, error) {
	ret := _m.Called(obj, settings)

	var r0 *models.OneTimeToken
	if rf, ok := ret.Get(0).(func(interface{}, *models.OneTimeTokenSettings) *models.OneTimeToken); ok {
		r0 = rf(obj, settings)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*models.OneTimeToken)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(interface{}, *models.OneTimeTokenSettings) error); ok {
		r1 = rf(obj, settings)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Get provides a mock function with given fields: token, obj
func (_m *OneTimeTokenServiceInterface) Get(token string, obj interface{}) error {
	ret := _m.Called(token, obj)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, interface{}) error); ok {
		r0 = rf(token, obj)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Use provides a mock function with given fields: token, obj
func (_m *OneTimeTokenServiceInterface) Use(token string, obj interface{}) error {
	ret := _m.Called(token, obj)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, interface{}) error); ok {
		r0 = rf(token, obj)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
