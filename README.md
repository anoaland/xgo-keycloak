# xgo-keycloak

Auth client for xgo

## Example Usage

```go
package server

import (
	"github.com/anoaland/xgo"
	auc "github.com/anoaland/xgo-keycloak"
)

type AppWebServer struct {
	AuthClient *auc.KeycloakWebAuthClient
	*xgo.WebServer
}

func New() AppWebServer {

	server := xgo.New()

	authClient := auc.New(os.Getenv("PUB_KEYCLOAK_URL"), os.Getenv("PUB_KEYCLOAK_REALM"), os.Getenv("KEYCLOAK_CLIENT_ID"), os.Getenv("KEYCLOAK_CLIENT_SECRET"))
	server.UseAuth(authClient, nil)

	// define the route you need
	api := server.XGroup("/api")

	return AppWebServer{
		authClient,
	}
}

```
