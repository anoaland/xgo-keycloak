package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/anoaland/xgo"
	"github.com/anoaland/xgo/utils"
	"github.com/gofiber/fiber/v2"
)

func (c KeycloakWebAuthClient) LoginWithGoogle(ctx context.Context, googleToken string) (*JWTGoogleWithUser, error) {

	googleRes, err := c.GoogleAuth(googleToken)

	if err != nil {
		log.Println("❌ ERROR_H2H_KEYCLOAK_GOOGLE_AUTH " + err.Error())
		if err.Error() == "User already exists" {
			return nil, err
		}
		return nil, xgo.NewHttpInternalError("ERROR_H2H_KEYCLOAK_GOOGLE_AUTH", err)
	}

	user, err := c.kk.GetUserInfo(ctx, googleRes.AccessToken, c.realm)

	if err != nil {
		return nil, xgo.NewHttpInternalError("ERROR_H2H_KEYCLOAK_GET_USER_INFO", err)

	}

	// get token exchange

	return &JWTGoogleWithUser{
		JWT:  *googleRes,
		User: *user,
	}, nil
}

func (c KeycloakWebAuthClient) GoogleAuth(token string) (*TokenSuccessResponse, error) {

	serviceUrl := c.url + "realms/" + c.realm + "/protocol/openid-connect/token"
	log.Println("🔥 h2h url : " + serviceUrl)

	args := fiber.AcquireArgs()
	args.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	args.Set("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token")
	args.Set("client_id", c.clientId)
	args.Set("client_secret", c.clientSecret)
	args.Set("subject_token", token)
	args.Set("subject_issuer", "google")
	args.Set("scope", "openid")

	httpClient := utils.HttpClient{
		Url:             serviceUrl,
		Method:          fiber.MethodPost,
		Args:            args,
		Payload:         nil,
		ResponseSuccess: &TokenSuccessResponse{},
		ResponseError:   &GoogleAuthErrorResponse{},
		ErrorPrefix:     "E_AUTH_GOOGLE",
	}

	httpClient.Headers = append(httpClient.Headers, utils.ContentTypeFormHeader())

	clientResp, err := httpClient.Send()
	if err != nil {
		respErr := new(GoogleAuthErrorResponse)
		json.Unmarshal([]byte(err.Error()), &respErr)
		log.Println(" ❌ ERROR URL KC GOOGLE : " + err.Error())

		if respErr.ErrorDescription != nil {
			return nil, fmt.Errorf(*respErr.ErrorDescription)
		}

		if respErr.Error != nil {
			return nil, err
		}
		return nil, err

	}

	return clientResp.(*TokenSuccessResponse), nil
}

func (c KeycloakWebAuthClient) GetUserInfoGoogle(token string) (*GoogleUserInfoResponse, error) {

	serviceUrl := "https://www.googleapis.com/oauth2/v2/userinfo"
	log.Println("🔥 h2h url : " + serviceUrl)

	headers := []utils.HttpClientHeaders{}

	headers = append(headers, utils.AuthorizationHeader(token))

	httpClient := utils.HttpClient{
		Url:             serviceUrl,
		Method:          fiber.MethodGet,
		Headers:         headers,
		Payload:         nil,
		ResponseSuccess: &GoogleUserInfoResponse{},
		ResponseError:   &GoogleUserInfoErrorResponse{},
		ErrorPrefix:     "E_OAUTH_USER_INFO_GOOGLE",
	}

	httpClient.Headers = append(httpClient.Headers, utils.ContentTypeFormHeader())

	clientResp, err := httpClient.Send()
	if err != nil {
		respErr := new(GoogleAuthErrorResponse)
		json.Unmarshal([]byte(err.Error()), &respErr)
		log.Println(" ❌ E_OAUTH_USER_INFO_GOOGLE" + err.Error())

		if respErr.ErrorDescription != nil {
			return nil, fmt.Errorf(*respErr.ErrorDescription)
		}

		if respErr.Error != nil {
			return nil, err
		}
		return nil, err

	}

	return clientResp.(*GoogleUserInfoResponse), nil
}

func (c KeycloakWebAuthClient) CheckFederationGoogle(userId string) (bool, error) {
	serviceAccountToken, err := c.getServiceToken(context.Background())
	if err != nil {
		return false, err
	}

	federatedIdentities, err := c.GetFederatedIdentityKeycloack(*serviceAccountToken, userId)
	if err != nil {
		return false, err
	}

	for _, federatedIdentity := range *federatedIdentities {
		if federatedIdentity.IdentityProvider == "google" {
			return true, nil
		}
	}

	return false, nil

}

func (c KeycloakWebAuthClient) GetFederatedIdentityKeycloack(token string, userId string) (*[]UserFederationKeycloack, error) {

	serviceUrl := c.url + "admin/realms/" + c.realm + "/users/" + userId + "/federated-identity"
	log.Println("🔥 h2h url : " + serviceUrl)

	headers := []utils.HttpClientHeaders{}

	headers = append(headers, utils.AuthorizationHeader(token))

	httpClient := utils.HttpClient{
		Url:             serviceUrl,
		Method:          fiber.MethodGet,
		Headers:         headers,
		Payload:         nil,
		ResponseSuccess: &[]UserFederationKeycloack{},
		ResponseError:   &GoogleAuthErrorResponse{},
		ErrorPrefix:     "E_OAUTH_KEYCLOACK_GET_FEDERATION_GOOGLE",
	}

	httpClient.Headers = append(httpClient.Headers, utils.ContentTypeFormHeader())

	clientResp, err := httpClient.Send()
	if err != nil {
		respErr := new(GoogleAuthErrorResponse)
		json.Unmarshal([]byte(err.Error()), &respErr)
		log.Println(" ❌ E_OAUTH_KEYCLOACK_GET_FEDERATION_GOOGLE" + err.Error())

		if respErr.ErrorDescription != nil {
			return nil, fmt.Errorf(*respErr.ErrorDescription)
		}

		if respErr.Error != nil {
			return nil, err
		}
		return nil, err

	}

	return clientResp.(*[]UserFederationKeycloack), nil
}

func (c KeycloakWebAuthClient) FederationGoogle(userId string, userIdGoogle string, usernameGoogle string) error {
	serviceUrl := c.url + "admin/realms/" + c.realm + "/users/" + userId + "/federated-identity/google"
	log.Println("🔥 h2h url : " + serviceUrl)

	serviceAccountToken, err := c.getServiceToken(context.Background())
	if err != nil {
		fmt.Println(" ❌ E_OAUTH_KEYCLOACK_GET_SERVICE_TOKEN" + err.Error())
		return err
	}

	payload := UserFederationRequestKeycloack{
		UserID:   userIdGoogle,
		UserName: usernameGoogle,
	}

	payloadMarshal, err := json.Marshal(payload)
	if err != nil {
		fmt.Println(" ❌ E_OAUTH_KEYCLOACK_MARSHAL_FEDERATION_GOOGLE" + err.Error())
		return err
	}

	headers := []utils.HttpClientHeaders{}

	headers = append(headers, utils.AuthorizationHeader(*serviceAccountToken))
	headers = append(headers, utils.JsonContentTypeHeader())

	httpClient := utils.HttpClient{
		Url:             serviceUrl,
		Method:          fiber.MethodPost,
		Headers:         headers,
		Payload:         payloadMarshal,
		ResponseSuccess: nil,
		ResponseError:   &GoogleAuthErrorResponse{},
		ErrorPrefix:     "E_OAUTH_KEYCLOACK_POST_FEDERATION_GOOGLE",
	}

	_, err = httpClient.Send()
	if err != nil {
		respErr := new(GoogleAuthErrorResponse)
		json.Unmarshal([]byte(err.Error()), &respErr)
		log.Println(" ❌ E_OAUTH_KEYCLOACK_GET_FEDERATION_GOOGLE" + err.Error())

		if respErr.ErrorDescription != nil {
			return fmt.Errorf(*respErr.ErrorDescription)
		}

		if respErr.Error != nil {
			return err
		}
		return err

	}

	return nil
}
