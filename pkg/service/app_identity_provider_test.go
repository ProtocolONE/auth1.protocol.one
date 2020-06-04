package service

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo/bson"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

var (
	idp1 = &models.AppIdentityProvider{ID: bson.NewObjectId(), Type: "type1", Name: "name1"}
	idp2 = &models.AppIdentityProvider{ID: bson.NewObjectId(), Type: "type2", Name: "name1"}

	space = &models.Space{
		ID:                bson.NewObjectId(),
		IdentityProviders: []*models.AppIdentityProvider{idp1, idp2},
	}
	app = &models.Application{SpaceId: space.ID}
)

type MemSpaces map[bson.ObjectId]*models.Space

func (m MemSpaces) CreateSpace(*models.Space) error { return nil }
func (m MemSpaces) UpdateSpace(*models.Space) error { return nil }
func (m MemSpaces) GetSpace(id bson.ObjectId) (*models.Space, error) {
	s, ok := m[id]
	if ok {
		return s, nil
	}
	return nil, errors.New("space not found")
}
func (m MemSpaces) AddIdentityProvider(space *models.Space, ip *models.AppIdentityProvider) error {
	return nil
}
func (m MemSpaces) UpdateIdentityProvider(space *models.Space, ip *models.AppIdentityProvider) error {
	return nil
}

var spaces = MemSpaces{space.ID: space}
var spacesNew repository.SpaceRepository

func TestIdentityProviderGetReturnProvider(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	p := ip.Get(app, idp1.ID)
	assert.Equal(t, idp1.ID, p.ID, "Incorrect identity provider")
}

func TestIdentityProviderGetReturnNil(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	assert.Nil(t, ip.Get(app, bson.NewObjectId()), "Identity provider must be empty")
}

func TestIdentityProvidersFindByTypeReturnProviders(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	assert.Len(t, ip.FindByType(app, "type1"), 1, "Invalid count providers")
}

func TestIdentityProvidersFindByTypeReturnEmptyProviders(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	assert.Len(t, ip.FindByType(app, "type3"), 0, "Invalid count providers")
}

func TestIdentityProvidersFindByTypeAndNameReturnProviders(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	p := ip.FindByTypeAndName(app, "type1", "name1")
	assert.Equal(t, "type1", p.Type, 1, "Invalid provider type")
	assert.Equal(t, "name1", p.Name, 1, "Invalid provider name")
}

func TestIdentityProvidersFindByTypeAndNameReturnEmptyProviders(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	assert.Nil(t, ip.FindByTypeAndName(app, "type1", "name2"), "Identity provider must be empty")
}

func TestIdentityProvidersGetTemplateReturnError(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	_, err := ip.GetTemplate("test")
	if err == nil {
		t.Error("Get unknown template must be return error")
	}

	assert.Equal(t, fmt.Sprintf(ErrorInvalidTemplate, "test"), err.Error())
}

func TestIdentityProvidersGetAvailableTemplates(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	assert.Len(t, ip.GetAvailableTemplates(), 4, "Invalid count available templates")
}

func TestIdentityProvidersGetAllTemplates(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	assert.Len(t, ip.GetAllTemplates(), len(ip.GetAvailableTemplates()), "Invalid count available templates")
}

func TestIdentityProvidersNormalizeSocialConnectionReturnErrorByInvalidName(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	err := ip.NormalizeSocialConnection(&models.AppIdentityProvider{Name: "test"})
	if err == nil {
		t.Error("Normalize connection must be return error")
	}

	assert.Equal(t, fmt.Sprintf(ErrorInvalidSocialProviderName, "test"), err.Error())
}

func TestIdentityProvidersNormalizeSocialConnectionSetDefaultValues(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	template, _ := ip.GetTemplate(models.AppIdentityProviderNameFacebook)
	ipc := &models.AppIdentityProvider{Name: models.AppIdentityProviderNameFacebook}
	ip.NormalizeSocialConnection(ipc)

	assert.Equal(t, template.DisplayName, ipc.DisplayName)
	assert.Equal(t, template.EndpointAuthURL, ipc.EndpointAuthURL)
	assert.Equal(t, template.EndpointTokenURL, ipc.EndpointTokenURL)
	assert.Equal(t, template.EndpointUserInfoURL, ipc.EndpointUserInfoURL)
	assert.Equal(t, template.ClientScopes, ipc.ClientScopes)
}

func TestIdentityProvidersNormalizeSocialConnectionInjectScopes(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	ipc := &models.AppIdentityProvider{Name: models.AppIdentityProviderNameFacebook, ClientScopes: []string{"scope1"}}
	ip.NormalizeSocialConnection(ipc)

	hasInjectScope := false
	for _, scope := range ipc.ClientScopes {
		if scope == "scope1" {
			hasInjectScope = true
		}
	}

	if hasInjectScope != true {
		t.Error("Unable to inject scope to the social provider")
	}
}

func TestIdentityProvidersNormalizeSocialConnectionRemoveDuplicateScopes(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	template, _ := ip.GetTemplate(models.AppIdentityProviderNameFacebook)
	ipc := &models.AppIdentityProvider{Name: models.AppIdentityProviderNameFacebook, ClientScopes: []string{"email"}}
	ip.NormalizeSocialConnection(ipc)

	assert.Len(t, ipc.ClientScopes, len(template.ClientScopes), "Unable to remove duplicate scopes")
}

func TestIdentityProvidersGetAuthUrlReturnWithScope(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	ipc := &models.AppIdentityProvider{ClientScopes: []string{"email"}}
	url, _ := ip.GetAuthUrl("http://localhost", ipc, "")

	assert.Regexp(t, "scope=email", url, "Scope has not been set")
}

func TestIdentityProvidersGetAuthUrlReturnImplodedUrlParameters(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	ipc := &models.AppIdentityProvider{EndpointAuthURL: "http://localhost/?param=value", ClientScopes: []string{"email"}}
	url, _ := ip.GetAuthUrl("http://localhost", ipc, "")

	assert.Regexp(t, regexp.MustCompile("http://localhost/\\?param=value(.*)"), url, "Url parameters has not been imploded")
}

func TestIdentityProvidersGetAuthUrl(t *testing.T) {
	ip := NewAppIdentityProviderService(spaces, spacesNew)
	ipc := &models.AppIdentityProvider{EndpointAuthURL: "http://localhost/", ClientID: "1", Name: "google"}
	url, _ := ip.GetAuthUrl("http://localhost", ipc, "")

	expected := "http://localhost/?client_id=1&redirect_uri=http%3A%2F%2Flocalhost%2Fapi%2Fproviders%2Fgoogle%2Fcallback&response_type=code&state=IiI%3D"
	assert.Equal(t, expected, url, "Invalid social auth url")
}
