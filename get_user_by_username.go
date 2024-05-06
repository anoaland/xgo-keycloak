package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/anoaland/xgo/utils"
	"github.com/gofiber/fiber/v2"
)

type UserSuccessResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
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

	fmt.Println(serviceUrl, "<<< iki service url")

	httpClient := utils.HttpClient{
		Url:             serviceUrl,
		Method:          fiber.MethodGet,
		Headers:         headers,
		Payload:         nil,
		ResponseSuccess: []UserSuccessResponse{},
		ResponseError:   UserErrorResponse{},
		ErrorPrefix:     "E_AUTH_GET_USER_BY_USERNAME",
		LogRequest:      true,
	}

	clientResp, err := httpClient.Send()

	if err != nil {
		respErr := new(UserErrorResponse)
		json.Unmarshal([]byte(err.Error()), &respErr)
		log.Println(" ❌ ERROR URL KC GET USER BY USERNAME : " + err.Error())

		if respErr.Error != nil {
			return nil, errors.New(*respErr.Error)
		}
		return nil, err
	}

	res := clientResp.([]interface{})

	if len(res) == 0 {
		return nil, errors.New("User not found")
	}

	user := res[0].(map[string]interface{})
	return &UserSuccessResponse{
		ID:       user["id"].(string),
		Username: user["username"].(string),
		Email:    user["email"].(string),
	}, nil
}
