package keycloak_go_adapter

import (
	"context"
	"github.com/Nerzal/gocloak/v11"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

//N.B KEYCLOAK MUST BE RUNNING
//From docker folder: docker compose -f keycloak.yml up

const serverUrl = "http://localhost:9080"
const clientId = "internal"
const realm = "entando"

var client = gocloak.NewClient(serverUrl)

func init() {
	Init(clientId, serverUrl, realm)
}

func TestAuthorized_rawprotect(t *testing.T) {
	var (
		authorized, httpStatus, err interface{}
		token                       *gocloak.JWT
	)

	token, _ = client.Login(context.Background(), "web_app", "-", realm, "user1", "user1")
	authorized, httpStatus, err = RawProtect(context.Background(), token.AccessToken, []string{}, false)

	assert.Equal(t, true, authorized)
	assert.Equal(t, http.StatusOK, httpStatus)
	assert.Nil(t, err)

	authorized, httpStatus, err = RawProtect(context.Background(), token.AccessToken, []string{}, true)

	assert.Equal(t, true, authorized)
	assert.Equal(t, http.StatusOK, httpStatus)
	assert.Nil(t, err)

	token, _ = client.Login(context.Background(), "web_app", "-", realm, "user2", "user2")
	authorized, httpStatus, err = RawProtect(context.Background(), token.AccessToken, []string{"first-role"}, false)

	assert.Equal(t, true, authorized)
	assert.Equal(t, http.StatusOK, httpStatus)
	assert.Nil(t, err)

	authorized, httpStatus, err = RawProtect(context.Background(), token.AccessToken, []string{"first-role"}, true)

	assert.Equal(t, true, authorized)
	assert.Equal(t, http.StatusOK, httpStatus)
	assert.Nil(t, err)

	token, _ = client.Login(context.Background(), "web_app", "-", realm, "user3", "user3")
	authorized, httpStatus, err = RawProtect(context.Background(), token.AccessToken, []string{"second-role"}, false)

	assert.Equal(t, true, authorized)
	assert.Equal(t, http.StatusOK, httpStatus)
	assert.Nil(t, err)

	authorized, httpStatus, err = RawProtect(context.Background(), token.AccessToken, []string{"first-role", "second-role1"}, true)

	assert.Equal(t, true, authorized)
	assert.Equal(t, http.StatusOK, httpStatus)
	assert.Nil(t, err)

	authorized, httpStatus, err = RawProtect(context.Background(), token.AccessToken, []string{"first-role", "second-role-fake"}, true)

	assert.Equal(t, true, authorized)
	assert.Equal(t, http.StatusOK, httpStatus)
	assert.Nil(t, err)

	authorized, httpStatus, err = RawProtect(context.Background(), token.AccessToken, []string{"first-role", "second-role"}, false)

	assert.Equal(t, true, authorized)
	assert.Equal(t, http.StatusOK, httpStatus)
	assert.Nil(t, err)

}

func TestUnauthorized_rawprotect(t *testing.T) {
	var (
		authorized, httpStatus, err interface{}
		token                       *gocloak.JWT
	)

	authorized, httpStatus, err = RawProtect(context.Background(), "broken-token", []string{}, false)

	assert.Equal(t, false, authorized)
	assert.Equal(t, http.StatusUnauthorized, httpStatus)
	assert.NotNil(t, err)

	token, _ = client.Login(context.Background(), "web_app", "-", realm, "user1", "user1")
	authorized, httpStatus, err = RawProtect(context.Background(), token.AccessToken, []string{"first-role"}, true)

	assert.Equal(t, false, authorized)
	assert.Equal(t, http.StatusForbidden, httpStatus)
	assert.Nil(t, err)

	token, _ = client.Login(context.Background(), "web_app", "-", realm, "user2", "user2")
	authorized, httpStatus, err = RawProtect(context.Background(), token.AccessToken, []string{"first-role", "second-role"}, false)

	assert.Equal(t, false, authorized)
	assert.Equal(t, http.StatusForbidden, httpStatus)
	assert.Nil(t, err)

	token, _ = client.Login(context.Background(), "web_app", "-", realm, "user3", "user3")
	authorized, httpStatus, err = RawProtect(context.Background(), token.AccessToken, []string{"first-role", "second-role-fake"}, false)

	assert.Equal(t, false, authorized)
	assert.Equal(t, http.StatusForbidden, httpStatus)
	assert.Nil(t, err)

}

func Test_protect(t *testing.T) {
	var (
		authorized, httpStatus, err interface{}
		token                       *gocloak.JWT
		request                     *http.Request
	)

	token, _ = client.Login(context.Background(), "web_app", "-", realm, "user1", "user1")

	request = httptest.NewRequest("GET", "http://example.com", nil)
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)

	authorized, httpStatus, err = Protect(request, []string{}, true)

	assert.Equal(t, true, authorized)
	assert.Equal(t, http.StatusOK, httpStatus)
	assert.Nil(t, err)

	request = httptest.NewRequest("GET", "http://example.com", nil)
	request.Header.Set("Authorization", "")

	authorized, httpStatus, err = Protect(request, []string{}, true)

	assert.Equal(t, false, authorized)
	assert.Equal(t, http.StatusUnauthorized, httpStatus)
	assert.NotNil(t, err)

	request = httptest.NewRequest("GET", "http://example.com", nil)
	request.Header.Set("Authorization", "fake token")

	authorized, httpStatus, err = Protect(request, []string{}, true)

	assert.Equal(t, false, authorized)
	assert.Equal(t, http.StatusUnauthorized, httpStatus)
	assert.NotNil(t, err)

	token, _ = client.Login(context.Background(), "web_app", "-", realm, "user1", "user1")

	request = httptest.NewRequest("GET", "http://example.com", nil)
	request.Header.Set("Authorization", token.AccessToken)

	assert.Equal(t, false, authorized)
	assert.Equal(t, http.StatusUnauthorized, httpStatus)
	assert.NotNil(t, err)

}
