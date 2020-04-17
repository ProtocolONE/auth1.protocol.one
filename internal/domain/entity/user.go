package entity

type User struct {
	ID            string
	AppID         string
	ExternalID    string
	Email         string
	EmailVerified bool
	Phone         string
	PhoneVerified bool
	Username      string
	Name          string
}
