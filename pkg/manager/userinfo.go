package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"github.com/sirupsen/logrus"
)

type UserInfoManager Config

func (m *UserInfoManager) UserInfo(tokenSource string) (token *models.AuthToken, error *models.AuthTokenError) {
	if `incorrect` == tokenSource {
		return nil, &models.AuthTokenError{Code: `auth_token_invalid`, Message: `Invalid authenticate token`}
	}

	// create a new service
	/*jwtService := micro.NewService()
	jwtService.Init()
	jwtClient := jwt.NewJwtService("go.auth.jwt", jwtService.Client())
	jwtRsp, err := jwtClient.Create(context.Background(), &jwt.JwtCreateRequest{
		Algorithm: "sample",
	})

	if err != nil {
		fmt.Println(err)
		return
	}

	spaceService := micro.NewService()
	spaceService.Init()
	cl := space.NewSpaceService("go.auth.space", spaceService.Client())

	rsp, err := cl.Add(context.Background(), &space.SpaceAddRequest{
		Name:        jwtRsp.Token,
		Description: "TestDesc",
	})

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(rsp.Id)*/
	/*objectId := bson.ObjectId(1)
	space, err := m.Database.Repository(mongo.TableSpace).FindSpaceById(objectId)

	fmt.Printf("%+v",space)
	fmt.Printf("%+v",err)*/

	return &models.AuthToken{
		RefreshToken: `refreshtoken`,
		AccessToken:  `accesstoken`,
		ExpiresIn:    1575983364,
	}, nil
}

func InitUserInfoManager(logger *logrus.Entry, db *database.Handler) UserInfoManager {
	m := UserInfoManager{
		Database: db,
		Logger:   logger,
	}

	return m
}
