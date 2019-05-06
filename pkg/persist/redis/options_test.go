package rediswatcher

import (
	"github.com/bmizerany/assert"
	"testing"
)

func TestOptions(t *testing.T) {
	o := WatcherOptions{
		RaiseOwn: false,
	}

	o.optionBuilder(RaiseOwn(true))
	assert.Equal(t, true, o.RaiseOwn, "RaiseOwn should be 'true'")
}

func (o *WatcherOptions) optionBuilder(setters ...WatcherOption) {
	for _, setter := range setters {
		setter(o)
	}
}
