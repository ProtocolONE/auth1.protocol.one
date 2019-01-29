package models

import (
	"auth-one-api/pkg/database"
	"go.uber.org/zap/zapcore"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"time"
)

type CaptchaRequiredError CommonError

type UserService struct {
	db *mgo.Database
}

type User struct {
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

type UserProfile struct {
	ID            bson.ObjectId `bson:"_id" json:"id"`
	AppID         bson.ObjectId `bson:"app_id" json:"app_id"`
	Email         string        `bson:"email" json:"email" validate:"required,email"`
	EmailVerified bool          `bson:"email_verified" json:"email_verified"`
}

type SignUpForm struct {
	ClientID   string `form:"client_id" json:"client_id" validate:"required"`
	Connection string `form:"connection" json:"connection" validate:"required"`
	Email      string `form:"email" json:"email" validate:"required,email"`
	Password   string `form:"password" json:"password" validate:"required"`
}

type AuthorizeForm struct {
	ClientID    string `query:"client_id" form:"client_id" json:"client_id" validate:"required"`
	Connection  string `query:"connection" form:"connection" json:"connection" validate:"required"`
	RedirectUri string `query:"redirect_uri" form:"redirect_uri" json:"redirect_uri"`
	State       string `query:"state" form:"state" json:"state"`
}

type AuthorizeResultForm struct {
	Code  string `query:"code" form:"code" json:"code" validate:"required"`
	State string `query:"state" form:"state" json:"state" validate:"required"`
}

type AuthorizeLinkForm struct {
	ClientID    string `query:"client_id" form:"client_id" json:"client_id" validate:"required"`
	Code        string `query:"code" form:"code" json:"code" validate:"required"`
	Action      string `query:"action" form:"action" json:"action" validate:"required"`
	Password    string `query:"password" form:"password" json:"password"`
	AccessToken string `query:"access_token" form:"access_token" json:"access_token"`
}

type LoginForm struct {
	ClientID string `form:"client_id" validate:"required" json:"client_id"`
	Email    string `form:"email" validate:"required,email" json:"email"`
	Password string `form:"password" validate:"required" json:"password"`
	Captcha  string `form:"captcha" json:"captcha"`
}

func (a *User) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ID", a.ID.String())
	enc.AddString("AppID", a.AppID.String())
	enc.AddString("Email", a.Email)
	enc.AddBool("EmailVerified", a.EmailVerified)
	enc.AddTime("CreatedAt", a.CreatedAt)
	enc.AddTime("UpdatedAt", a.UpdatedAt)

	return nil
}

func (a *AuthorizeForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)
	enc.AddString("Connection", a.Connection)
	enc.AddString("RedirectUri", a.RedirectUri)
	enc.AddString("State", a.State)

	return nil
}

func (a *AuthorizeResultForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Code", a.Code)
	enc.AddString("State", a.State)

	return nil
}

func (a *AuthorizeLinkForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)
	enc.AddString("Code", a.Code)
	enc.AddString("Action", a.Action)
	enc.AddString("Password", "[HIDDEN]")
	enc.AddString("AccessToken", "[HIDDEN]")

	return nil
}

func (a *LoginForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)
	enc.AddString("Email", a.Email)
	enc.AddString("Password", "[HIDDEN]")
	enc.AddString("Captcha", a.Captcha)

	return nil
}

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
