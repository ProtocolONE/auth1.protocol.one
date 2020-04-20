package entity

import "time"

type User struct {
	ID    string
	AppID string
	//
	Email         string
	EmailVerified bool
	Phone         string
	PhoneVerified bool
	//
	Username       string
	UniqueUsername bool
	Name           string
	Picture        string
	//
	LastIp      string
	LastLogin   time.Time
	LoginsCount int
	Blocked     bool
	DeviceID    []string
	//
	CreatedAt time.Time
	UpdatedAt time.Time
}
