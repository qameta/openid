package openid_client

type JsonKey struct {
	Type           string `json:"type"`
	KeyId          string `json:"keyId"`
	Key            string `json:"key"`
	ExpirationDate string `json:"expirationDate"`
	UserId         string `json:"userId"`
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}
