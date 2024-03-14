package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log"

	"github.com/anoaland/xgo"
	"github.com/anoaland/xgo/utils"
	"github.com/gofiber/fiber/v2"
)

func (c KeycloakWebAuthClient) LoginWithGoogle(ctx context.Context, googleToken string) (*JWTGoogleWithUser, error) {

	googleRes, err := c.GoogleAuth(googleToken)

	if err != nil {
		log.Println("❌ ERROR_H2H_KEYCLOAK_GOOGLE_AUTH " + err.Error())
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

		if respErr.Error != nil {
			return nil, errors.New(*respErr.Error)
		}
		return nil, err

	}

	return clientResp.(*TokenSuccessResponse), nil
}
