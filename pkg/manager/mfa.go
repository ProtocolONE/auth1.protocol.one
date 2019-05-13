package manager

import (
	"context"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/globalsign/mgo/bson"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

// MFAManagerInterface describes of methods for the manager.
type MFAManagerInterface interface {
	// MFAChallenge is temporary unused.
	MFAChallenge(*models.MfaChallengeForm) *models.GeneralError

	// MFAVerify verifies the one-time MFA token.
	MFAVerify(echo.Context, *models.MfaVerifyForm) *models.GeneralError

	// MFAAdd adds mfa provider for the user.
	//
	// If successful, a secret key will be generated, a list of backup codes and a
	// qr-code to add an authenticator to the program.
	MFAAdd(echo.Context, *models.MfaAddForm) (*models.MfaAuthenticator, *models.GeneralError)
}

// MFAManager is the mfa manager.
type MFAManager struct {
	r              service.InternalRegistry
	authLogService service.AuthLogServiceInterface
	userService    service.UserServiceInterface
	mfaService     service.MfaServiceInterface
}

// NewMFAManager return new mfa manager.
func NewMFAManager(h database.MgoSession, r service.InternalRegistry) MFAManagerInterface {
	m := &MFAManager{
		r:              r,
		authLogService: service.NewAuthLogService(h),
		mfaService:     service.NewMfaService(h),
		userService:    service.NewUserService(h),
	}

	return m
}

func (m *MFAManager) MFAChallenge(form *models.MfaChallengeForm) *models.GeneralError {
	//TODO: For OTP over SMS/Email. Undone

	return nil
}

func (m *MFAManager) MFAVerify(ctx echo.Context, form *models.MfaVerifyForm) *models.GeneralError {
	mp := &models.UserMfaToken{}
	if err := m.r.OneTimeTokenService().Get(form.Token, mp); err != nil {
		return &models.GeneralError{Code: "mfa_token", Message: models.ErrorCannotUseToken, Err: errors.Wrap(err, "Unable to use OneTimeToken")}
	}

	rsp, err := m.r.MfaService().Check(context.TODO(), &proto.MfaCheckDataRequest{
		ProviderID: mp.MfaProvider.ID.String(),
		UserID:     mp.UserIdentity.UserID.String(),
		Code:       form.Code,
	})
	if err != nil {
		return &models.GeneralError{Code: "common", Message: models.ErrorMfaCodeInvalid, Err: errors.Wrap(err, "Unable to verify MFA code")}
	}

	if rsp.Result != true {
		return &models.GeneralError{Code: "common", Message: models.ErrorMfaCodeInvalid, Err: errors.New(models.ErrorMfaCodeInvalid)}
	}

	_, err = m.userService.Get(mp.UserIdentity.UserID)
	if err != nil {
		return &models.GeneralError{Code: "email", Message: models.ErrorLoginIncorrect, Err: errors.Wrap(err, "Unable to get user")}
	}

	return nil
}

func (m *MFAManager) MFAAdd(ctx echo.Context, form *models.MfaAddForm) (token *models.MfaAuthenticator, error *models.GeneralError) {
	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(form.ClientId))
	if err != nil {
		return nil, &models.GeneralError{Code: "client_id", Message: models.ErrorClientIdIncorrect, Err: errors.Wrap(err, "Unable to load application")}
	}

	p, err := m.mfaService.Get(bson.ObjectIdHex(form.ProviderId))
	if err != nil || p == nil || p.AppID != app.ID {
		if err == nil {
			err = errors.New("Provider not equal application")
		}
		return nil, &models.GeneralError{Code: "provider_id", Message: models.ErrorProviderIdIncorrect, Err: errors.WithStack(err)}
	}

	c, err := helper.GetTokenFromAuthHeader(ctx.Request().Header)
	if err != nil {
		return nil, &models.GeneralError{Code: "client_id", Message: models.ErrorClientIdIncorrect, Err: errors.Wrap(err, "Unable to validate bearer token")}
	}

	rsp, err := m.r.MfaService().Create(context.TODO(), &proto.MfaCreateDataRequest{
		ProviderID: p.ID.String(),
		AppName:    app.Name,
		UserID:     c.UserId.String(),
		Email:      c.Email,
		QrSize:     300,
	})
	if err != nil {
		return nil, &models.GeneralError{Code: "common", Message: models.ErrorMfaClientAdd, Err: errors.Wrap(err, "Unable to add MFA")}
	}

	up := &models.MfaUserProvider{
		UserID:     c.UserId,
		ProviderID: p.ID,
	}
	if err = m.mfaService.AddUserProvider(up); err != nil {
		return nil, &models.GeneralError{Code: "common", Message: models.ErrorMfaClientAdd, Err: errors.Wrap(err, "Unable to add MFA to user")}
	}

	return &models.MfaAuthenticator{
		ID:            p.ID,
		Type:          p.Type,
		ObbChannel:    p.Channel,
		Secret:        rsp.SecretKey,
		BarcodeUri:    rsp.QrCodeURL,
		RecoveryCodes: rsp.RecoveryCode,
	}, nil
}
