package helper

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetRandStringCheckLength(t *testing.T) {
	length := 5
	str := GetRandString(length)
	assert.Lenf(t, str, length, "The length of the string must be %d characters.", length)
}

func TestGetRandStringCheckCharacters(t *testing.T) {
	length := 5
	str := GetRandString(length)
	assert.Regexp(t, "^([A-z0-9]{1,})$", str, "The string must contain only letters and numbers.")
}
