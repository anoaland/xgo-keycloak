package auth

type GoogleAuthErrorResponse struct {
	Error            *string `json:"error"`
	ErrorDescription *string `json:"error_description"`
}

type TokenSuccessResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token"`
	NotBeforePolicy  int64  `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

type BasicUser struct {
	ID       string
	Email    string
	Username string
}
type JWTGoogleWithUser struct {
	User BasicUser
	JWT  TokenSuccessResponse
}

type GooglePayloadRequestDTO struct {
	GrantType          string `json:"grant_type"`
	RequestedTokenType string `json:"requested_token_type"`
	ClientID           string `json:"client_id"`
	ClientSecret       string `json:"client_secret"`
	SubjectToken       string `json:"subject_token"`
	SubjectIssuer      string `json:"subject_issuer"`
}
