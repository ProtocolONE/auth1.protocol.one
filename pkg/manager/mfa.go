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

func (m *MFAManager) MFAChallenge(form *models.MfaChallengeForm) (error *models.CommonError) {
	//TODO: For OTP over SMS/Email. Undone

	return nil
}

func (m *MFAManager) MFAVerify(ctx echo.Context, form *models.MfaVerifyForm) (token *models.AuthToken, error *models.CommonError) {
	mp := &models.UserMfaToken{}
	if err := m.r.OneTimeTokenService().Get(form.Token, mp); err != nil {
		m.Logger.Error(
			"Unable to use token an application",
			zap.Object("MfaVerifyForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `mfa_token`, Message: models.ErrorCannotUseToken}
	}

	rsp, err := m.r.MfaService().Check(context.TODO(), &proto.MfaCheckDataRequest{
		ProviderID: mp.MfaProvider.ID.String(),
		UserID:     mp.UserIdentity.UserID.String(),
		Code:       form.Code,
	})

	if err != nil {
		m.Logger.Error(
			"Unable to verify MFA code",
			zap.Error(err),
		)
	}

	if err != nil || rsp.Result != true {
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorMfaCodeInvalid}
	}

	app, err := m.r.ApplicationService().Get(mp.UserIdentity.ApplicationID)
	if err != nil {
		m.Logger.Error("Unable to load application", zap.Error(err))
		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	user, err := m.userService.Get(mp.UserIdentity.UserID)
	if err != nil {
		m.Logger.Error(
			"Unable to get user",
			zap.Object("UserIdentity", mp.UserIdentity),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
	}

	if err := m.authLogService.Add(ctx, user, ""); err != nil {
		m.Logger.Error(
			"Unable to add user auth log for application",
			zap.Object("User", user),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	return nil, nil
}

func (m *MFAManager) MFAAdd(ctx echo.Context, form *models.MfaAddForm) (token *models.MfaAuthenticator, error *models.CommonError) {

	a, err := m.r.ApplicationService().Get(bson.ObjectIdHex(form.ClientId))
	if err != nil {
		m.Logger.Error("Unable to load application", zap.Error(err))
		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	p, err := m.mfaService.Get(bson.ObjectIdHex(form.ProviderId))
	if err != nil || p.AppID != a.ID {
		m.Logger.Error(
			"Unable to get MFA provider for application",
			zap.Object("MfaAddForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `provider_id`, Message: models.ErrorProviderIdIncorrect}
	}

	c, err := helper.GetTokenFromAuthHeader(ctx.Request().Header)
	if err != nil {
		m.Logger.Error(
			"Unable to validate bearer token",
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorClientIdIncorrect}
	}

	rsp, err := m.r.MfaService().Create(context.TODO(), &proto.MfaCreateDataRequest{
		ProviderID: p.ID.String(),
		AppName:    a.Name,
		UserID:     c.UserId.String(),
		Email:      c.Email,
		QrSize:     300,
	})
	if err != nil {
		m.Logger.Error(
			"Unable to add MFA",
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorMfaClientAdd}
	}

	up := &models.MfaUserProvider{
		UserID:     c.UserId,
		ProviderID: p.ID,
	}
	if err = m.mfaService.AddUserProvider(up); err != nil {
		m.Logger.Error(
			"Unable to add MFA to user",
			zap.Object("mfaProvide", p),
			zap.String("jwtUserId", c.UserId.String()),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorMfaClientAdd}
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
