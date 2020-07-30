package entity

import "time"

type Profile struct {
	UserID string
	//
	Address1 *string
	Address2 *string
	City     *string
	State    *string
	Country  *string
	Zip      *string
	//
	PhotoURL  *string
	FirstName *string
	LastName  *string
	BirthDate *time.Time
	//
	Language *string
	Currency *string
	//
	Role *string
}
