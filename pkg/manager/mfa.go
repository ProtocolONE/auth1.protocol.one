package manager

import (
	"context"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/go-redis/redis"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type MFAManager struct {
	Redis          *redis.Client
	Logger         *zap.Logger
	r              service.InternalRegistry
	authLogService *models.AuthLogService
	userService    *models.UserService
	mfaService     *models.MfaService
}

func NewMFAManager(h *mgo.Session, l *zap.Logger, redis *redis.Client, r service.InternalRegistry) *MFAManager {
	m := &MFAManager{
		Redis:          redis,
		Logger:         l,
		r:              r,
		authLogService: models.NewAuthLogService(h),
		mfaService:     models.NewMfaService(h),
		userService:    models.NewUserService(h),
	}

	return m
}

func (m *MFAManager) MFAChallenge(form *models.MfaChallengeForm) (error *models.GeneralError) {
	//TODO: For OTP over SMS/Email. Undone

	return nil
}

func (m *MFAManager) MFAVerify(ctx echo.Context, form *models.MfaVerifyForm) (token *models.AuthToken, error *models.GeneralError) {
	mp := &models.UserMfaToken{}
	if err := m.r.OneTimeTokenService().Get(form.Token, mp); err != nil {
		return nil, &models.GeneralError{Code: `mfa_token`, Message: models.ErrorCannotUseToken, Error: errors.Wrap(err, "Unable to use OneTimeToken")}
	}

	rsp, err := m.r.MfaService().Check(context.TODO(), &proto.MfaCheckDataRequest{
		ProviderID: mp.MfaProvider.ID.String(),
		UserID:     mp.UserIdentity.UserID.String(),
		Code:       form.Code,
	})
	if err != nil {
		return nil, &models.GeneralError{Code: `common`, Message: models.ErrorMfaCodeInvalid, Error: errors.Wrap(err, "Unable to verify MFA code")}
	}

	if rsp.Result != true {
		return nil, &models.GeneralError{Code: `common`, Message: models.ErrorMfaCodeInvalid}
	}

	user, err := m.userService.Get(mp.UserIdentity.UserID)
	if err != nil {
		return nil, &models.GeneralError{Code: `email`, Message: models.ErrorLoginIncorrect, Error: errors.Wrap(err, "Unable to get user")}
	}

	if err := m.authLogService.Add(ctx, user, ""); err != nil {
		return nil, &models.GeneralError{Code: `common`, Message: models.ErrorAddAuthLog, Error: errors.Wrap(err, "Unable to add user auth log")}
	}

	return nil, nil
}

func (m *MFAManager) MFAAdd(ctx echo.Context, form *models.MfaAddForm) (token *models.MfaAuthenticator, error *models.GeneralError) {
	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(form.ClientId))
	if err != nil {
		return nil, &models.GeneralError{Code: `client_id`, Message: models.ErrorClientIdIncorrect, Error: errors.Wrap(err, "Unable to load application")}
	}

	p, err := m.mfaService.Get(bson.ObjectIdHex(form.ProviderId))
	if err != nil || p.AppID != app.ID {
		return nil, &models.GeneralError{Code: `provider_id`, Message: models.ErrorProviderIdIncorrect, Error: errors.Wrap(err, "Unable to get MFA provider for application")}
	}

	c, err := helper.GetTokenFromAuthHeader(ctx.Request().Header)
	if err != nil {
		return nil, &models.GeneralError{Code: `client_id`, Message: models.ErrorClientIdIncorrect, Error: errors.Wrap(err, "Unable to validate bearer token")}
	}

	rsp, err := m.r.MfaService().Create(context.TODO(), &proto.MfaCreateDataRequest{
		ProviderID: p.ID.String(),
		AppName:    app.Name,
		UserID:     c.UserId.String(),
		Email:      c.Email,
		QrSize:     300,
	})
	if err != nil {
		return nil, &models.GeneralError{Code: `common`, Message: models.ErrorMfaClientAdd, Error: errors.Wrap(err, "Unable to add MFA")}
	}

	up := &models.MfaUserProvider{
		UserID:     c.UserId,
		ProviderID: p.ID,
	}
	if err = m.mfaService.AddUserProvider(up); err != nil {
		return nil, &models.GeneralError{Code: `common`, Message: models.ErrorMfaClientAdd, Error: errors.Wrap(err, "Unable to add MFA to user")}
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
