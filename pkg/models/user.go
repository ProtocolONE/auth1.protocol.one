package models

import (
	"auth-one-api/pkg/database"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"time"
)

type (
	CaptchaRequiredError CommonError

	UserService struct {
		db *mgo.Database
	}

	User struct {
		ID            bson.ObjectId `bson:"_id" json:"id"`
		AppID         bson.ObjectId `bson:"app_id" json:"app_id"`
		Email         string        `bson:"email" json:"email" validate:"required,email"`
		EmailVerified bool          `bson:"email_verified" json:"email_verified"`
		PhoneNumber   string        `bson:"phone_number" json:"phone_number"`
		PhoneVerified bool          `bson:"phone_verified" json:"phone_verified"`
		Username      string        `bson:"username" json:"username"`
		Name          string        `bson:"name" json:"name"`
		Picture       string        `bson:"picture" json:"picture"`
		LastIp        string        `bson:"last_ip" json:"last_ip"`
		LastLogin     time.Time     `bson:"last_login" json:"last_login"`
		LoginsCount   int           `bson:"logins_count" json:"logins_count"`
		Blocked       bool          `bson:"blocked" json:"blocked"`
		CreatedAt     time.Time     `bson:"created_at" json:"created_at"`
		UpdatedAt     time.Time     `bson:"updated_at" json:"updated_at"`
	}

	UserProfile struct {
		ID            bson.ObjectId `bson:"_id" json:"id"`
		AppID         bson.ObjectId `bson:"app_id" json:"app_id"`
		Email         string        `bson:"email" json:"email" validate:"required,email"`
		EmailVerified bool          `bson:"email_verified" json:"email_verified"`
	}

	SignUpForm struct {
		ClientID   string `form:"client_id" validate:"required"`
		Connection string `form:"connection" validate:"required"`
		Email      string `form:"email" validate:"required,email"`
		Password   string `form:"password" validate:"required"`
	}

	AuthorizeForm struct {
		ClientID    string `query:"client_id" form:"client_id" validate:"required"`
		Connection  string `query:"connection" form:"connection" validate:"required"`
		RedirectUri string `query:"redirect_uri" form:"redirect_uri"`
		State       string `query:"state" form:"state"`
	}

	AuthorizeResultForm struct {
		Code  string `query:"code" form:"code" validate:"required"`
		State string `query:"state" form:"state" validate:"required"`
	}

	AuthorizeLinkForm struct {
		ClientID    string `query:"client_id" form:"client_id" validate:"required"`
		Code        string `query:"code" form:"code" validate:"required"`
		Action      string `query:"action" form:"action" validate:"required"`
		Password    string `query:"password" form:"password"`
		AccessToken string `query:"access_token" form:"access_token"`
	}

	LoginForm struct {
		ClientID string `form:"client_id" validate:"required"`
		Email    string `form:"email" validate:"required,email"`
		Password string `form:"password" validate:"required"`
		Captcha  string `form:"captcha"`
	}
)

func (m CaptchaRequiredError) Error() string {
	return m.Message
}

func (m *CaptchaRequiredError) GetCode() string {
	return m.Code
}

func (m *CaptchaRequiredError) GetMessage() string {
	return m.Message
}

func NewUserService(dbHandler *database.Handler) *UserService {
	return &UserService{dbHandler.Session.DB(dbHandler.Name)}
}

func (us UserService) Create(user *User) error {
	if err := us.db.C(database.TableUser).Insert(user); err != nil {
		return err
	}

	return nil
}

func (us UserService) Update(user *User) error {
	if err := us.db.C(database.TableUser).UpdateId(user.ID, user); err != nil {
		return err
	}

	return nil
}

func (us UserService) Get(id bson.ObjectId) (*User, error) {
	u := &User{}
	if err := us.db.C(database.TableUser).
		FindId(id).
		One(&u); err != nil {
		return nil, err
	}

	return u, nil
}

func (us UserService) GetByEmail(app *Application, email string) (*User, error) {
	u := &User{}
	/*b, _ := us.GetUserIdentityByEmail(app, email, "password")
	r := mgo.DBRef{
		ID:         b.ID,
		Database:   us.db.Name,
		Collection: database.TableUser,
	}

	if err := us.db.FindRef(r).CC(database.TableUser).
		Find(bson.D{{"email", email}}).
		One(&u); err != nil {
		return nil, err
	}*/

	return u, nil
}
