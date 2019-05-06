package validator

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsPasswordValidMinLength(t *testing.T) {
	app := &models.Application{PasswordSettings: &models.PasswordSettings{Min: 1, Max: 2, RequireNumber: false, RequireUpper: false, RequireSpecial: false}}
	assert.True(t, IsPasswordValid(app, "1"))

	app = &models.Application{PasswordSettings: &models.PasswordSettings{Min: 2, Max: 2, RequireNumber: false, RequireUpper: false, RequireSpecial: false}}
	assert.False(t, IsPasswordValid(app, "1"))
}

func TestIsPasswordValidMaxLength(t *testing.T) {
	app := &models.Application{PasswordSettings: &models.PasswordSettings{Min: 1, Max: 2, RequireNumber: false, RequireUpper: false, RequireSpecial: false}}
	assert.True(t, IsPasswordValid(app, "12"))

	app = &models.Application{PasswordSettings: &models.PasswordSettings{Min: 2, Max: 2, RequireNumber: false, RequireUpper: false, RequireSpecial: false}}
	assert.False(t, IsPasswordValid(app, "123"))
}

func TestIsPasswordValidRequireNumber(t *testing.T) {
	app := &models.Application{PasswordSettings: &models.PasswordSettings{Min: 1, Max: 10, RequireNumber: false, RequireUpper: false, RequireSpecial: false}}
	assert.True(t, IsPasswordValid(app, "asd"))

	app = &models.Application{PasswordSettings: &models.PasswordSettings{Min: 2, Max: 10, RequireNumber: true, RequireUpper: false, RequireSpecial: false}}
	assert.False(t, IsPasswordValid(app, "qwe"))

	app = &models.Application{PasswordSettings: &models.PasswordSettings{Min: 2, Max: 10, RequireNumber: true, RequireUpper: false, RequireSpecial: false}}
	assert.True(t, IsPasswordValid(app, "qwe123"))
}

func TestIsPasswordValidRequireUpper(t *testing.T) {
	app := &models.Application{PasswordSettings: &models.PasswordSettings{Min: 1, Max: 10, RequireNumber: false, RequireUpper: false, RequireSpecial: false}}
	assert.True(t, IsPasswordValid(app, "asd"))

	app = &models.Application{PasswordSettings: &models.PasswordSettings{Min: 2, Max: 10, RequireNumber: false, RequireUpper: true, RequireSpecial: false}}
	assert.False(t, IsPasswordValid(app, "qwe"))

	app = &models.Application{PasswordSettings: &models.PasswordSettings{Min: 2, Max: 10, RequireNumber: false, RequireUpper: true, RequireSpecial: false}}
	assert.True(t, IsPasswordValid(app, "qweQwe"))
}

func TestIsPasswordValidRequireSpecial(t *testing.T) {
	app := &models.Application{PasswordSettings: &models.PasswordSettings{Min: 1, Max: 10, RequireNumber: false, RequireUpper: false, RequireSpecial: false}}
	assert.True(t, IsPasswordValid(app, "asd"))

	app = &models.Application{PasswordSettings: &models.PasswordSettings{Min: 2, Max: 10, RequireNumber: false, RequireUpper: false, RequireSpecial: true}}
	assert.False(t, IsPasswordValid(app, "qwe"))

	app = &models.Application{PasswordSettings: &models.PasswordSettings{Min: 2, Max: 10, RequireNumber: false, RequireUpper: false, RequireSpecial: true}}
	assert.True(t, IsPasswordValid(app, "qwe@"))
}
