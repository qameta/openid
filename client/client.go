package client

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	json "github.com/json-iterator/go"
	"github.com/qameta/openid-client/config"
	"github.com/qameta/openid-client/models"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"time"
)

type Client[T any] struct {
	headers http.Header
	conf    *config.OpenIDConfig
}

func NewClient[T any](conf *config.OpenIDConfig) *Client[T] {
	var client = Client[T]{
		headers: http.Header{},
		conf:    conf,
	}

	var jsonKey models.JsonKey
	unmarshalErr := json.Unmarshal(conf.Key, &jsonKey)
	if unmarshalErr != nil {
		log.Fatalf("failed unmarshalling key: %v", unmarshalErr)
	}

	var exchangeToken = jwt.Token{
		Header: map[string]interface{}{
			"alg": jwt.SigningMethodRS256.Alg(),
			"kid": jsonKey.KeyId,
		},
		Claims: jwt.MapClaims{
			"iss": jsonKey.UserId,
			"sub": jsonKey.UserId,
			"aud": conf.IDPConfig.Issuer,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(24 * time.Hour).Unix(),
		},
		Method: jwt.SigningMethodRS256,
	}

	var keyPEMBlock, _ = pem.Decode([]byte(jsonKey.Key))
	if keyPEMBlock == nil {
		log.Fatalf("failed decoding PEM block: %v", keyPEMBlock)
	}

	var privateKey, keyErr = x509.ParsePKCS1PrivateKey(keyPEMBlock.Bytes)
	if keyErr != nil {
		log.Fatalf("failed parsing private key: %v", keyErr)
	}

	var signedToken, signatureErr = exchangeToken.SignedString(privateKey)
	if signatureErr != nil {
		log.Fatalf("failed signing token: %v", signatureErr)
	}

	var form = url.Values{}

	form.Set("grant_type", config.DefaultGrant)
	form.Set("assertion", signedToken)
	form.Set("scope", "openid")

	var response, respErr = http.PostForm(conf.IDPConfig.TokenEndpoint, form)
	if respErr != nil {
		log.Fatalf("failed to exchange token: %v", respErr)
	}

	var authResponse models.AccessTokenResponse
	parseTokenErr := json.NewDecoder(response.Body).Decode(&authResponse)
	if parseTokenErr != nil {
		log.Fatalf("failed to parse token: %v", parseTokenErr)
	}

	client.headers.Add("Authorization", fmt.Sprintf("%s %s", authResponse.TokenType, authResponse.AccessToken))
	client.headers.Add("Content-Type", "application/json")

	return &client
}

func (c *Client[T]) Get(url string) (*T, error) {
	var request, reqErr = http.NewRequest(http.MethodGet, url, nil)
	if reqErr != nil {
		return nil, fmt.Errorf("failed to create request: %v", reqErr)
	}

	request.Header = c.headers

	var response, respErr = http.DefaultClient.Do(request)
	if respErr != nil {
		return nil, fmt.Errorf("failed to get response: %v", respErr)
	}

	var result T
	var unmarshalErr = json.NewDecoder(response.Body).Decode(&result)
	if unmarshalErr != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", unmarshalErr)
	}

	return &result, nil
}

func (c *Client[T]) Post(url string, body T) (*T, error) {
	var serializedBody, serErr = json.Marshal(body)
	if serErr != nil {
		return nil, serErr
	}

	var postBody = bytes.NewReader(serializedBody)
	var request, reqErr = http.NewRequest(http.MethodPost, url, postBody)
	if reqErr != nil {
		return nil, fmt.Errorf("failed to create request: %v", reqErr)
	}

	request.Header = c.headers

	var response, respErr = http.DefaultClient.Do(request)
	if respErr != nil {
		return nil, fmt.Errorf("failed to get response: %v", respErr)
	}

	var result T
	var unmarshalErr = json.NewDecoder(response.Body).Decode(&result)
	if unmarshalErr != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", unmarshalErr)
	}

	return &result, nil
}

func (c *Client[T]) Put(url string, body T) (*T, error) {
	var serializedBody, serErr = json.Marshal(body)
	if serErr != nil {
		return nil, serErr
	}

	var putBody = bytes.NewReader(serializedBody)
	var request, reqErr = http.NewRequest(http.MethodPut, url, putBody)
	if reqErr != nil {
		return nil, fmt.Errorf("failed to create request: %v", reqErr)
	}

	request.Header = c.headers

	var response, respErr = http.DefaultClient.Do(request)
	if respErr != nil {
		return nil, fmt.Errorf("failed to get response: %v", respErr)
	}

	var result T
	var unmarshalErr = json.NewDecoder(response.Body).Decode(&result)
	if unmarshalErr != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", unmarshalErr)
	}

	return &result, nil
}

func (c *Client[T]) Delete(url string) error {
	var request, reqErr = http.NewRequest(http.MethodDelete, url, nil)
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %v", reqErr)
	}

	request.Header = c.headers

	var _, respErr = http.DefaultClient.Do(request)
	if respErr != nil {
		return fmt.Errorf("failed to delete response: %v", respErr)
	}

	return respErr
}
