package service

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo/bson"
	"github.com/stretchr/testify/assert"
)

var (
	idp1 = entity.IdentityProvider{
		ID:   entity.IdentityProviderID(bson.NewObjectId().Hex()),
		Type: entity.IDProviderTypePassword,
		Name: "name1",
	}
	idp2 = entity.IdentityProvider{
		ID:   entity.IdentityProviderID(bson.NewObjectId().Hex()),
		Type: entity.IDProviderTypeSocial,
		Name: "name1",
	}

	space = &entity.Space{
		ID:                entity.SpaceID(bson.NewObjectId().Hex()),
		IdentityProviders: entity.IdentityProviders{idp1, idp2},
	}
	app = &models.Application{SpaceId: bson.ObjectIdHex(string(space.ID))}
)

var spacesNew = repository.OneSpaceRepo(space)

func TestIdentityProvidersFindByTypeAndNameReturnProviders(t *testing.T) {
	ip := NewAppIdentityProviderService(spacesNew)
	p := ip.FindByTypeAndName(app, "password", "name1")
	assert.Equal(t, "password", p.Type, 1, "Invalid provider type")
	assert.Equal(t, "name1", p.Name, 1, "Invalid provider name")
}

func TestIdentityProvidersFindByTypeAndNameReturnEmptyProviders(t *testing.T) {
	ip := NewAppIdentityProviderService(spacesNew)
	assert.Nil(t, ip.FindByTypeAndName(app, "password", "name2"), "Identity provider must be empty")
}

func TestIdentityProvidersGetTemplateReturnError(t *testing.T) {
	ip := NewAppIdentityProviderService(spacesNew)
	_, err := ip.GetTemplate("test")
	if err == nil {
		t.Error("Get unknown template must be return error")
	}

	assert.Equal(t, fmt.Sprintf(ErrorInvalidTemplate, "test"), err.Error())
}

func TestIdentityProvidersGetAvailableTemplates(t *testing.T) {
	ip := NewAppIdentityProviderService(spacesNew)
	assert.Len(t, ip.GetAvailableTemplates(), 4, "Invalid count available templates")
}

func TestIdentityProvidersGetAllTemplates(t *testing.T) {
	ip := NewAppIdentityProviderService(spacesNew)
	assert.Len(t, ip.GetAllTemplates(), len(ip.GetAvailableTemplates()), "Invalid count available templates")
}

// func TestIdentityProvidersNormalizeSocialConnectionReturnErrorByInvalidName(t *testing.T) {
// 	ip := NewAppIdentityProviderService(spacesNew)
// 	err := ip.NormalizeSocialConnection(&models.AppIdentityProvider{Name: "test"})
// 	if err == nil {
// 		t.Error("Normalize connection must be return error")
// 	}

// 	assert.Equal(t, fmt.Sprintf(ErrorInvalidSocialProviderName, "test"), err.Error())
// }

// func TestIdentityProvidersNormalizeSocialConnectionSetDefaultValues(t *testing.T) {
// 	ip := NewAppIdentityProviderService(spacesNew)
// 	template, _ := ip.GetTemplate(models.AppIdentityProviderNameFacebook)
// 	ipc := &models.AppIdentityProvider{Name: models.AppIdentityProviderNameFacebook}
// 	ip.NormalizeSocialConnection(ipc)

// 	assert.Equal(t, template.DisplayName, ipc.DisplayName)
// 	assert.Equal(t, template.EndpointAuthURL, ipc.EndpointAuthURL)
// 	assert.Equal(t, template.EndpointTokenURL, ipc.EndpointTokenURL)
// 	assert.Equal(t, template.EndpointUserInfoURL, ipc.EndpointUserInfoURL)
// 	assert.Equal(t, template.ClientScopes, ipc.ClientScopes)
// }

// func TestIdentityProvidersNormalizeSocialConnectionInjectScopes(t *testing.T) {
// 	ip := NewAppIdentityProviderService(spacesNew)
// 	ipc := &models.AppIdentityProvider{Name: models.AppIdentityProviderNameFacebook, ClientScopes: []string{"scope1"}}
// 	ip.NormalizeSocialConnection(ipc)

// 	hasInjectScope := false
// 	for _, scope := range ipc.ClientScopes {
// 		if scope == "scope1" {
// 			hasInjectScope = true
// 		}
// 	}

// 	if hasInjectScope != true {
// 		t.Error("Unable to inject scope to the social provider")
// 	}
// }

// func TestIdentityProvidersNormalizeSocialConnectionRemoveDuplicateScopes(t *testing.T) {
// 	ip := NewAppIdentityProviderService(spacesNew)
// 	template, _ := ip.GetTemplate(models.AppIdentityProviderNameFacebook)
// 	ipc := &models.AppIdentityProvider{Name: models.AppIdentityProviderNameFacebook, ClientScopes: []string{"email"}}
// 	ip.NormalizeSocialConnection(ipc)

// 	assert.Len(t, ipc.ClientScopes, len(template.ClientScopes), "Unable to remove duplicate scopes")
// }

func TestIdentityProvidersGetAuthUrlReturnWithScope(t *testing.T) {
	ip := NewAppIdentityProviderService(spacesNew)
	ipc := &models.AppIdentityProvider{ClientScopes: []string{"email"}}
	url, _ := ip.GetAuthUrl("http://localhost", ipc, "")

	assert.Regexp(t, "scope=email", url, "Scope has not been set")
}

func TestIdentityProvidersGetAuthUrlReturnImplodedUrlParameters(t *testing.T) {
	ip := NewAppIdentityProviderService(spacesNew)
	ipc := &models.AppIdentityProvider{EndpointAuthURL: "http://localhost/?param=value", ClientScopes: []string{"email"}}
	url, _ := ip.GetAuthUrl("http://localhost", ipc, "")

	assert.Regexp(t, regexp.MustCompile("http://localhost/\\?param=value(.*)"), url, "Url parameters has not been imploded")
}

func TestIdentityProvidersGetAuthUrl(t *testing.T) {
	ip := NewAppIdentityProviderService(spacesNew)
	ipc := &models.AppIdentityProvider{EndpointAuthURL: "http://localhost/", ClientID: "1", Name: "google"}
	url, _ := ip.GetAuthUrl("http://localhost", ipc, "")

	expected := "http://localhost/?client_id=1&redirect_uri=http%3A%2F%2Flocalhost%2Fapi%2Fproviders%2Fgoogle%2Fcallback&response_type=code&state=IiI%3D"
	assert.Equal(t, expected, url, "Invalid social auth url")
}
