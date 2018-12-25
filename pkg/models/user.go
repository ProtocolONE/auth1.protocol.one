package models

import (
	"auth-one-api/pkg/database"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"time"
)

type (
	UserService struct {
		db *mgo.Database
	}

	User struct {
		ID            bson.ObjectId `bson:"_id" json:"id"`
		AppID         bson.ObjectId `bson:"app_id" json:"app_id"`
		Email         string        `bson:"email" json:"email" validate:"required,email"`
		EmailVerified bool          `bson:"email_verified" json:"email_verified"`
		Password      string        `bson:"password" json:"password" validate:"required"`
		CreatedAt     time.Time     `bson:"created_at" json:"created_at"`
		UpdatedAt     time.Time     `bson:"updated_at" json:"updated_at"`
	}

	SignUpForm struct {
		ClientId   string `json:"client_id" form:"client_id" validate:"required"`
		Connection string `json:"connection" form:"connection" validate:"required"`
		Email      string `json:"email" form:"email" validate:"required,email"`
		Password   string `json:"password" form:"password" validate:"required"`
	}

	LoginForm struct {
		ClientId   string `json:"client_id" form:"client_id" validate:"required"`
		Connection string `json:"connection" form:"connection" validate:"required"`
		Email      string `json:"email" form:"email" validate:"required,email"`
		Password   string `json:"password" form:"password" validate:"required"`
		Captcha    string `json:"captcha" form:"captcha"`
	}
)

func NewUserService(h *database.Handler) *UserService {
	return &UserService{h.Session.DB(h.Name)}
}

func (us UserService) CreateUser(u *User) error {
	if err := us.db.C(database.TableUser).Insert(u); err != nil {
		return err
	}

	return nil
}

func (us UserService) UpdateUser(u *User) error {
	if err := us.db.C(database.TableUser).UpdateId(u.ID, u); err != nil {
		return err
	}

	return nil
}

func (us UserService) GetUser(id bson.ObjectId) (*User, error) {
	u := &User{}
	if err := us.db.C(database.TableUser).
		FindId(id).
		One(&u); err != nil {
		return nil, err
	}

	return u, nil
}

func (us UserService) GetUserByEmail(a Application, email string) (*User, error) {
	u := &User{}
	if err := us.db.C(database.TableUser).
		Find(bson.D{{"email", email}}).
		One(&u); err != nil {
		return nil, err
	}

	return u, nil
}
