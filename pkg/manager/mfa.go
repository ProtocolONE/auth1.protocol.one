package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/models"
	"context"
	"fmt"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/go-redis/redis"
	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2/bson"
	"net/http"
)

type MFAManager Config

func (m *MFAManager) MFAChallenge(form *models.MfaChallengeForm) (error *models.CommonError) {
	//TODO: For OTP over SMS/Email. Undone

	return nil
}

func (m *MFAManager) MFAVerify(ctx echo.Context, form *models.MfaVerifyForm) (token *models.AuthToken, error *models.CommonError) {
	mp := &models.UserMfaToken{}
	ottSettings := &models.OneTimeTokenSettings{}
	os := models.NewOneTimeTokenService(m.Redis, ottSettings)
	if err := os.Get(form.Token, mp); err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to use token an application [%s] with error: %s", form.Code, err.Error()))
		return nil, &models.CommonError{Code: `mfa_token`, Message: models.ErrorCannotUseToken}
	}

	rsp, err := m.MfaService.Check(context.TODO(), &proto.MfaCheckDataRequest{
		ProviderID: mp.MfaProvider.ID.String(),
		UserID:     mp.UserIdentity.UserID.String(),
		Code:       form.Code,
	})
	fmt.Printf("%v", rsp)
	if err != nil || rsp.Result != true {
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to verify MFA code: %s", err.Error()))
		}
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorMfaCodeInvalid}
	}

	as := models.NewApplicationService(m.Database)
	a, err := as.Get(mp.UserIdentity.AppID)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to get application [%s] with error: %s", mp.UserIdentity.AppID, err.Error()))
		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	us := models.NewUserService(m.Database)
	u, err := us.Get(mp.UserIdentity.UserID)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to get user [%s] with error: %s", mp.UserIdentity.UserID, err.Error()))
		return nil, &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
	}

	t, err := helper.CreateAuthToken(ctx, as, u)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to create user [%s] auth token an application [%s] with error: %s", u.ID, a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: err.Error()}
	}

	als := models.NewAuthLogService(m.Database)
	if err := als.Add(ctx, u, t.RefreshToken); err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to add user [%s] auth log an application [%s] with error: %s", u.ID, a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	cs, err := as.LoadSessionSettings()
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to load session settings an application [%s] with error: %s", a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	c, err := models.NewCookie(a, u).Crypt(cs)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to create user [%s] cookie an application [%s] with error: %s", u.ID, a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	http.SetCookie(ctx.Response(), c)

	return t, nil
}

func (m *MFAManager) MFAAdd(ctx echo.Context, form *models.MfaAddForm) (token *models.MfaAuthenticator, error *models.CommonError) {
	as := models.NewApplicationService(m.Database)
	a, err := as.Get(bson.ObjectIdHex(form.ClientId))
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to receive client id [%s] with error: %s", form.ClientId, err.Error()))
		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ms := models.NewMfaService(m.Database)
	p, err := ms.Get(bson.ObjectIdHex(form.ProviderId))
	if err != nil || p.AppID != a.ID {
		m.Logger.Warning(fmt.Sprintf("Unable to get MFA provider [%s] an application [%s] with error: %s", form.ProviderId, form.ClientId, err.Error()))
		return nil, &models.CommonError{Code: `provider_id`, Message: models.ErrorProviderIdIncorrect}
	}

	c, err := helper.GetTokenFromAuthHeader(*as, ctx.Request().Header)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to validate bearer token: %s", err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorClientIdIncorrect}
	}

	rsp, err := m.MfaService.Create(context.TODO(), &proto.MfaCreateDataRequest{
		ProviderID: p.ID.String(),
		AppName:    a.Name,
		UserID:     c.UserId.String(),
		Email:      c.Email,
		QrSize:     300,
	})
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to add MFA: %s", err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorMfaClientAdd}
	}

	up := &models.MfaUserProvider{
		UserID:     c.UserId,
		ProviderID: p.ID,
	}
	if err = ms.AddUserProvider(up); err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to add MFA [%s] to user [%s]: %s", p.ID, c.UserId, err.Error()))
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

func InitMFAManager(logger *logrus.Entry, h *database.Handler, redis *redis.Client, ms proto.MfaService) MFAManager {
	m := MFAManager{
		Logger:     logger,
		Database:   h,
		Redis:      redis,
		MfaService: ms,
	}

	return m
}
