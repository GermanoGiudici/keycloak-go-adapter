package main

import (
	"context"
	keycloak_go_adapter "github.com/GermanoGiudici/keycloak-go-adapter"
	"github.com/Nerzal/gocloak/v11"
	"log"
)

/*func main() {
	client := gocloak.NewClient("http://localhost:9080")
	token, _ := client.Login(context.Background(), "web_app", "-", "entando", "et-first-role", "et-first-role")
	log.Default().Println("Token: " + token.AccessToken)

	accessToken, claims, error := client.DecodeAccessToken(context.Background(), token.AccessToken+"2", "entando")

	log.Default().Println("accessToken: " + accessToken.Raw)
	log.Default().Println(error)

	const clientId string = "internal"
	requestedRoles := []string{"et-first-role"}

	roles := funk.Get(claims, "resource_access."+clientId+".roles")
	if roles == nil {
		log.Default().Println("nil")
	} else {
		matchedRoles := funk.Filter(roles, func(elem interface{}) bool {
			return funk.Contains(requestedRoles, elem)
		})
		log.Default().Println(len(matchedRoles.([]interface{})) == len(requestedRoles))
	}

}
*/

func main() {
	serverUrl := "http://localhost:9080"
	clientId := "internal"
	realm := "entando"

	client := gocloak.NewClient(serverUrl)
	token, _ := client.Login(context.Background(), "web_app", "-", realm, "et-first-role", "et-first-role")
	keycloak_go_adapter.Init(clientId, serverUrl, realm)
	authorized, httpStatus, err := keycloak_go_adapter.RawProtect(context.Background(), token.AccessToken, []string{"et-first-role"}, false)
	log.Default().Println(authorized)
	log.Default().Println(httpStatus)
	log.Default().Println(err)

}
