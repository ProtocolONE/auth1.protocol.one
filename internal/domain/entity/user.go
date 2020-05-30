package entity

import "time"

type UserID string

type User struct {
	// ID is the id of user.
	ID UserID

	// SpaceID is the id of space to which user belongs
	SpaceID SpaceID

	// Email is the email address of the user.
	Email string

	// EmailVerified is status of verification user address.
	EmailVerified bool

	// PhoneNumber is the phone number of the user.
	PhoneNumber string

	// PhoneVerified is status of verification user phone.
	PhoneVerified bool

	// Username is the nickname of the user.
	Username string

	// Name is the name of the user. Contains first anf last name.
	Name string

	// Picture is the avatar of the user.
	Picture string

	// LastIp returns the ip of the last login.
	// LastIp string

	// LastLogin returns the timestamp of the last login.
	// LastLogin time.Time

	// LoginsCount contains count authorization for the user.
	// LoginsCount int

	// DeviceID is unique user client identifier
	// DeviceID []string

	// Blocked is status of user blocked.
	Blocked bool

	// CreatedAt is timestamp of the user creation.
	CreatedAt time.Time

	// UpdatedAt is timestamp of the last update.
	UpdatedAt time.Time
}
