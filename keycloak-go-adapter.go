package keycloak_go_adapter

import (
	"context"
	"errors"
	"github.com/Nerzal/gocloak/v11"
	"github.com/thoas/go-funk"
	"net/http"
	"strings"
)

type kCAdapterConfig struct {
	clientId      string
	serverUrl     string
	realm         string
	goCloakClient gocloak.GoCloak
}

var config *kCAdapterConfig

func Init(clientId string, serverUrl string, realm string) {
	config = &kCAdapterConfig{
		clientId:      clientId,
		serverUrl:     serverUrl,
		realm:         realm,
		goCloakClient: gocloak.NewClient(serverUrl),
	}
}

func Protect(r *http.Request, roles []string, any bool) (bool, int, error) {
	//extract access token from the request
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < 1 {
		return false, http.StatusUnauthorized, errors.New("authorization header not present")
	}
	rawToken := strings.Split(authHeader, " ")[1]
	return RawProtect(r.Context(), rawToken, roles, any)
}

func RawProtect(c context.Context, rawToken string, roles []string, any bool) (bool, int, error) {
	//decode access token
	accessToken, claims, err := config.goCloakClient.DecodeAccessToken(c, rawToken, config.realm)

	if accessToken == nil {
		return false, http.StatusUnauthorized, err
	}

	if claims == nil && len(roles) > 0 {
		return false, http.StatusForbidden, err
	}

	//check roles
	if len(roles) > 0 {
		//match the requested roles with the granted ones

		//get roles from clientid
		userResourceRoles := funk.Get(claims, "resource_access."+config.clientId+".roles")
		if userResourceRoles == nil {
			return false, http.StatusForbidden, nil
		} else {
			matchedRoles := funk.Filter(userResourceRoles, func(elem interface{}) bool {
				return funk.Contains(roles, elem)
			})

			if (any && len(matchedRoles.([]interface{})) == 0) || (!any && len(matchedRoles.([]interface{})) != len(roles)) {
				return false, http.StatusForbidden, nil
			}
		}
	}

	return true, http.StatusOK, nil
}
