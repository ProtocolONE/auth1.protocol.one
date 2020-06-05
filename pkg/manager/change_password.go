package manager

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"text/template"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/globalsign/mgo/bson"
	"github.com/pkg/errors"
)

// ChangePasswordManagerInterface describes of methods for the manager.
type ChangePasswordManagerInterface interface {
	// ChangePasswordStart initiates a process for changing a user's password.
	// The method creates a one-time token and sends it to the user's email.
	ChangePasswordStart(*models.ChangePasswordStartForm) *models.GeneralError

	// ChangePasswordVerify validates a one-time token sent by email and, if successful, changes the user's password.
	ChangePasswordVerify(*models.ChangePasswordVerifyForm) *models.GeneralError

	// ChangePasswordCheck verifies the token and returns user's email from token
	ChangePasswordCheck(token string) (string, error)
}

// ChangePasswordManager is the change password manager.
type ChangePasswordManager struct {
	r                       service.InternalRegistry
	userIdentityService     service.UserIdentityServiceInterface
	identityProviderService service.AppIdentityProviderServiceInterface
	ApiCfg                  *config.Server
	TplCfg                  *config.MailTemplates
}

// NewChangePasswordManager return new change password manager.
func NewChangePasswordManager(db database.MgoSession, ir service.InternalRegistry, apiCfg *config.Server, tplCfg *config.MailTemplates) ChangePasswordManagerInterface {
	m := &ChangePasswordManager{
		ApiCfg:                  apiCfg,
		TplCfg:                  tplCfg,
		r:                       ir,
		userIdentityService:     service.NewUserIdentityService(db),
		identityProviderService: service.NewAppIdentityProviderService(ir.SpaceService(), ir.Spaces()),
	}

	return m
}

func (m *ChangePasswordManager) ChangePasswordStart(form *models.ChangePasswordStartForm) *models.GeneralError {

	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		return &models.GeneralError{Code: "client_id", Message: models.ErrorClientIdIncorrect, Err: errors.Wrap(err, "Unable to load application")}
	}

	space, err := m.r.Spaces().FindByID(context.TODO(), entity.SpaceID(app.SpaceId.Hex()))
	if err != nil {
		return &models.GeneralError{Code: "client_id", Message: models.ErrorUnknownError, Err: errors.New("Unable to get application space")}
	}

	ipc := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
	if ipc == nil {
		return &models.GeneralError{Code: "client_id", Message: models.ErrorUnknownError, Err: errors.New("Unable to get identity provider")}
	}

	ui, err := m.userIdentityService.Get(ipc, form.Email)
	if err != nil {
		return &models.GeneralError{Code: "email", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to get user identity by email")}
	}

	if ui == nil || ui.ID == "" {
		// INFO: Do not need to disclose the login
		return nil
	}

	ottSettings := &models.OneTimeTokenSettings{
		Length: space.PasswordSettings.TokenLength,
		TTL:    space.PasswordSettings.TokenTTL,
	}
	token, err := m.r.OneTimeTokenService().Create(&models.ChangePasswordTokenSource{
		Email:     form.Email,
		ClientID:  form.ClientID,
		Challenge: form.Challenge,
		Subject:   ui.UserID.Hex(),
	}, ottSettings)
	if err != nil {
		return &models.GeneralError{Code: "common", Message: models.ErrorUnableCreateOttSettings, Err: errors.Wrap(err, "Unable to create OneTimeToken")}
	}

	b, err := ioutil.ReadFile(m.TplCfg.ChangePasswordTpl)
	tmpl, err := template.New("mail").Parse(string(b))
	if err != nil {
		// todo: fix params
		return &models.GeneralError{Code: "internal"}
	}
	w := bytes.Buffer{}
	err = tmpl.Execute(&w, struct {
		UserName         string
		PlatformName     string
		ResetLink        string
		SupportPortalUrl string
	}{
		UserName:         ui.Username,
		PlatformName:     m.TplCfg.PlatformName,
		ResetLink:        fmt.Sprintf("%s/change-password?login_challenge=%s&token=%s", m.TplCfg.PlatformUrl, form.Challenge, token.Token),
		SupportPortalUrl: m.TplCfg.SupportPortalUrl,
	})
	if err != nil {
		return &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to build reset password mail")}
	}
	fmt.Println(w.String())
	if err := m.r.Mailer().Send(form.Email, "Change password token", w.String()); err != nil {
		return &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to send mail with change password token")}
	}

	return nil
}

func (m *ChangePasswordManager) ChangePasswordVerify(form *models.ChangePasswordVerifyForm) *models.GeneralError {
	if form.PasswordRepeat != form.Password {
		return &models.GeneralError{Code: "password_repeat", Message: models.ErrorPasswordRepeat, Err: errors.New(models.ErrorPasswordRepeat)}
	}

	ts := &models.ChangePasswordTokenSource{}
	if err := m.r.OneTimeTokenService().Use(form.Token, ts); err != nil {
		return &models.GeneralError{Code: "common", Message: models.ErrorCannotUseToken, Err: errors.Wrap(err, "Unable to use OneTimeToken")}
	}

	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(ts.ClientID))
	if err != nil {
		return &models.GeneralError{Code: "client_id", Message: models.ErrorClientIdIncorrect, Err: errors.Wrap(err, "Unable to load application")}
	}

	space, err := m.r.Spaces().FindByID(context.TODO(), entity.SpaceID(app.SpaceId.Hex()))
	if err != nil {
		return &models.GeneralError{Code: "client_id", Message: models.ErrorUnknownError, Err: errors.New("Unable to get application space")}
	}

	if false == space.PasswordSettings.IsValid(form.Password) {
		return &models.GeneralError{Code: "password", Message: models.ErrorPasswordIncorrect, Err: errors.New(models.ErrorPasswordIncorrect)}
	}

	ipc := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
	if ipc == nil {
		return &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.New("Unable to get identity provider")}
	}

	ui, err := m.userIdentityService.Get(ipc, ts.Email)
	if err != nil || ui.ID == "" {
		if err == nil {
			err = errors.New("User identity not found")
		}
		return &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to get user identity")}
	}

	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: space.PasswordSettings.BcryptCost})
	ui.Credential, err = be.Digest(form.Password)
	if err != nil {
		return &models.GeneralError{Code: "password", Message: models.ErrorCryptPassword, Err: errors.Wrap(err, "Unable to crypt password")}
	}

	if err = m.userIdentityService.Update(ui); err != nil {
		return &models.GeneralError{Code: "password", Message: models.ErrorUnableChangePassword, Err: errors.Wrap(err, "Unable to update password")}
	}

	return nil
}

func (m *ChangePasswordManager) ChangePasswordCheck(token string) (string, error) {
	ts := &models.ChangePasswordTokenSource{}
	if err := m.r.OneTimeTokenService().Get(token, ts); err != nil {
		return "", errors.New("unable to get OneTimeToken")
	}

	return ts.Email, nil
}
