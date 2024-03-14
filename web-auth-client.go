package auth

import (
	"context"
	"fmt"

	"github.com/Nerzal/gocloak/v13"
)

type User interface {
	AsAppUser(payload *gocloak.UserInfo) any
	any
}

type KeycloakWebAuthClient struct {
	kk           *gocloak.GoCloak
	url          string
	realm        string
	clientId     string
	clientSecret string
	mapUser      User
}

func New(url string, realm string, clientId string, clientSecret string, mapUser User) *KeycloakWebAuthClient {
	kk := gocloak.NewClient(url)

	return &KeycloakWebAuthClient{
		kk:           kk,
		url:          url,
		realm:        realm,
		clientId:     clientId,
		clientSecret: clientSecret,
		mapUser:      mapUser,
	}
}

func (c KeycloakWebAuthClient) GetUserFromToken(token string) (interface{}, error) {
	user, err := c.kk.GetUserInfo(context.Background(), token, c.realm)

	if err != nil {
		return nil, err
	}

	return c.mapUser.AsAppUser(user), nil
}

func (c KeycloakWebAuthClient) VerifyEmail(ID string) error {
	serviceAccountToken, err := c.getServiceToken(context.Background())
	if err != nil {
		return err
	}
	verifyEmail := true
	err = c.kk.UpdateUser(context.Background(), *serviceAccountToken, c.realm, gocloak.User{
		ID:            &ID,
		EmailVerified: &verifyEmail,
	})

	if err != nil {
		return err
	}

	return nil
}

func (c KeycloakWebAuthClient) GetUserByUserID(ctx context.Context, id string) (*gocloak.User, error) {
	serviceAccountToken, err := c.getServiceToken(ctx)
	if err != nil {
		return nil, err
	}
	user, err := c.kk.GetUserByID(ctx, *serviceAccountToken, c.realm, id)

	if err != nil {
		return nil, err
	}

	return user, nil

}

/*
@Param userId must be a valid user ID and lower case!
*/
func (c KeycloakWebAuthClient) UserHasPassword(ctx context.Context, userId string) (bool, error) {
	serviceAccountToken, err := c.getServiceToken(ctx)
	if err != nil {
		return false, err
	}
	credentials, err := c.kk.GetCredentials(ctx, *serviceAccountToken, c.realm, userId)

	if err != nil {
		return false, err
	}

	hasPassword := false

	// Iterate through credentials and check if type is "password"
	for _, cred := range credentials {

		typePassword := "password"
		if *cred.Type == typePassword {

			hasPassword = true

		}
	}

	return hasPassword, nil

}

func (c KeycloakWebAuthClient) Login(ctx context.Context, usernameOrEmail string, password string) (*gocloak.JWT, error) {
	return c.kk.Login(ctx, c.clientId, c.clientSecret, c.realm, usernameOrEmail, password)
}

func (c KeycloakWebAuthClient) RefreshToken(ctx context.Context, refreshToken string) (*gocloak.JWT, error) {
	return c.kk.RefreshToken(ctx, refreshToken, c.clientId, c.clientSecret, c.realm)
}

func (c KeycloakWebAuthClient) RevokeToken(ctx context.Context, token string) error {
	return c.kk.RevokeToken(ctx, c.realm, c.clientId, c.clientSecret, token)
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

/*
@Param userId must be a valid user ID and lower case!
*/
func (c KeycloakWebAuthClient) SetPasswordUser(ctx context.Context, userId string, password string) error {
	serviceAccountToken, err := c.getServiceToken(ctx)
	if err != nil {
		return err
	}

	err = c.kk.SetPassword(ctx, *serviceAccountToken, userId, c.realm, password, false)
	// err = c.SetPasswordByHttpReq(*serviceAccountToken, userId, password)
	if err != nil {
		fmt.Println("❌ ERROR_H2H_KEYCLOAK_SET_PASSWORD_HTTP_REQUEST " + err.Error())
		return err
	}

	return nil
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
