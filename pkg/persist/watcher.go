package persist

type Watcher interface {
	// SetUpdateCallback sets the callback function that the watcher will call
	// when the date in DB has been changed by other instances.
	SetUpdateCallback(string, func(string))

	// Update calls the update callback of other instances to synchronize their policy.
	Update(string, string) error

	// Release watcher resources.
	Close() error
}
