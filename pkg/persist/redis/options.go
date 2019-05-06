package rediswatcher

type WatcherOptions struct {
	RaiseOwn bool
}

type WatcherOption func(*WatcherOptions)

func RaiseOwn(filterOwn bool) WatcherOption {
	return func(options *WatcherOptions) {
		options.RaiseOwn = filterOwn
	}
}
