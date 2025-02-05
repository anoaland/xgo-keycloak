package auth

import (
	"context"
	"encoding/json"
	"log"

	stdError "errors"

	"github.com/anoaland/xgo"
	"github.com/anoaland/xgo/errors"
	"github.com/anoaland/xgo/utils"
	"github.com/gofiber/fiber/v2"
)

type UserSuccessResponse struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"emailVerified"`
}

type UserErrorResponse struct {
	Error *string `json:"error"`
}

func (c KeycloakWebAuthClient) GetUserByUsername(username string) (*UserSuccessResponse, error) {
	token, err := c.getServiceToken(context.Background())

	if err != nil {
		return nil, err
	}

	headers := []utils.HttpClientHeaders{}

	headers = append(headers, utils.AuthorizationHeader(*token))

	serviceUrl := c.url + "admin/realms/" + c.realm + "/users?username=" + username

	httpClient := utils.HttpClient{
		Url:             serviceUrl,
		Method:          fiber.MethodGet,
		Headers:         headers,
		Payload:         nil,
		ResponseSuccess: []UserSuccessResponse{},
		ResponseError:   UserErrorResponse{},
		ErrorPrefix:     "E_AUTH_GET_USER_BY_USERNAME",
	}

	clientResp, err := httpClient.Send()

	if err != nil {
		log.Println(" ❌ ERROR URL KC GET USER BY USERNAME : " + err.Error())

		respErr := new(UserErrorResponse)

		err = json.Unmarshal([]byte(err.Error()), &respErr)
		if err != nil {
			return nil, err
		}

		if respErr.Error != nil {
			return nil, errors.NewHttpError("KEYCLOAK_GET_USER_BY_USERNAME", stdError.New(*respErr.Error),
				fiber.StatusInternalServerError, 2)
		}

		return nil, err
	}

	res := clientResp.([]interface{})

	if len(res) == 0 {
		return nil, xgo.NewHttpNotFoundError("KEYCLOAK_USER_NOT_FOUND", stdError.New(c.UserNotFoundMessage))
	}

	user := res[0].(map[string]interface{})
	return &UserSuccessResponse{
		ID:            user["id"].(string),
		Username:      user["username"].(string),
		Email:         user["email"].(string),
		EmailVerified: user["emailVerified"].(bool),
	}, nil
}
