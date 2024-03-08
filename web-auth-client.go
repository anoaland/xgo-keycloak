package auth

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
	"github.com/anoaland/xgo/auth"
)

type KeycloakWebAuthClient struct {
	kk              *gocloak.GoCloak
	url             string
	realm           string
	clientId        string
	clientSecret    string
	jwtSignatureKey []byte
}

func New(url string, realm string, clientId string, clientSecret string) *KeycloakWebAuthClient {
	kk := gocloak.NewClient(url)

	return &KeycloakWebAuthClient{
		kk:           kk,
		url:          url,
		realm:        realm,
		clientId:     clientId,
		clientSecret: clientSecret,
	}
}

func (c KeycloakWebAuthClient) GetUserFromToken(token string) (*auth.AppUser, error) {
	user, err := c.kk.GetUserInfo(context.Background(), token, c.realm)

	if err != nil {
		return nil, err
	}

	var kuser = KeycloakAppUser{user}

	return kuser.AsAppUser(), nil
}

func (c KeycloakWebAuthClient) Login(ctx context.Context, usernameOrEmail string, password string) (*gocloak.JWT, error) {
	return c.kk.Login(ctx, c.clientId, c.clientSecret, c.realm, usernameOrEmail, password)
}

func (c KeycloakWebAuthClient) RefreshToken(ctx context.Context, refreshToken string) (*gocloak.JWT, error) {
	return c.kk.RefreshToken(ctx, refreshToken, c.clientId, c.clientSecret, c.realm)
}

func (c KeycloakWebAuthClient) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	return c.kk.RevokeToken(ctx, c.realm, c.clientId, c.clientSecret, refreshToken)
}

func (c KeycloakWebAuthClient) RevokeToken(ctx context.Context, refreshToken string) error {
	return c.kk.RevokeToken(ctx, c.realm, c.clientId, c.clientSecret, refreshToken)
}

// Register registers a new user in Keycloak.
//
// ctx - the context.Context for the operation.
// user - the user details to be registered.
// password - the password for the new user.
// Returns the user ID and any error that occurs.
func (c KeycloakWebAuthClient) Register(ctx context.Context, user gocloak.User, password string) (*string, error) {

	serviceAccountToken, err := c.getServiceToken(ctx)
	if err != nil {
		return nil, err
	}

	userId, err := c.kk.CreateUser(ctx, *serviceAccountToken, c.realm, user)

	if err != nil {
		return nil, err
	}

	err = c.kk.SetPassword(ctx, *serviceAccountToken, userId, c.realm, password, false)
	if err != nil {
		return nil, err
	}

	return &userId, nil
}

func (c KeycloakWebAuthClient) DeleteUser(ctx context.Context, userId string) error {
	serviceAccountToken, err := c.getServiceToken(ctx)
	if err != nil {
		return err
	}

	err = c.kk.DeleteUser(ctx, *serviceAccountToken, c.realm, userId)

	return err
}

func (c KeycloakWebAuthClient) getServiceToken(ctx context.Context) (*string, error) {
	// this works as well
	// token, err := auth.client.LoginAdmin(c, "dd-admin", "dd-admin", realm)

	jwt, err := c.kk.GetToken(ctx, c.realm, gocloak.TokenOptions{
		ClientID:     &c.clientId,
		ClientSecret: &c.clientSecret,
		GrantType:    gocloak.StringP("client_credentials"),
	})

	if err != nil {
		return nil, err
	}

	return &jwt.AccessToken, nil
}
