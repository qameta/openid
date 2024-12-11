package client

import (
	"fmt"
	"io"
	"net/http"
	"os"

	json "github.com/json-iterator/go"
	log "github.com/sirupsen/logrus"
	"github.com/thoas/go-funk"
)

const DefaultGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"
const DiscoveryPath = ".well-known/openid-configuration"

var issuerURI = os.Getenv("ISSUER_URI")
var keyPath = os.Getenv("AUTH_KEY_PATH")

type IDPConfiguration struct {
	Issuer                                             string   `json:"issuer"`
	AuthorizationEndpoint                              string   `json:"authorization_endpoint"`
	TokenEndpoint                                      string   `json:"token_endpoint"`
	IntrospectionEndpoint                              string   `json:"introspection_endpoint"`
	UserinfoEndpoint                                   string   `json:"userinfo_endpoint"`
	RevocationEndpoint                                 string   `json:"revocation_endpoint"`
	EndSessionEndpoint                                 string   `json:"end_session_endpoint"`
	DeviceAuthorizationEndpoint                        string   `json:"device_authorization_endpoint"`
	JwksURI                                            string   `json:"jwks_uri"`
	ScopesSupported                                    []string `json:"scopes_supported"`
	ResponseTypesSupported                             []string `json:"response_types_supported,omitempty"`
	ResponseModesSupported                             []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported                              []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported                   []string `json:"id_token_signing_alg_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported             []string `json:"request_object_signing_alg_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                  []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported         []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	RevocationEndpointAuthMethodsSupported             []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported    []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpointAuthMethodsSupported          []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	ClaimsSupported                                    []string `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported                      []string `json:"code_challenge_methods_supported,omitempty"`
	UILocalesSupported                                 []string `json:"ui_locales_supported,omitempty"`
	RequestParameterSupported                          bool     `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported                       bool     `json:"request_uri_parameter_supported,omitempty"`
}

type OpenIDConfig struct {
	IDPConfig *IDPConfiguration
	Key       []byte
}

func NewOpenIDConfig() (*OpenIDConfig, error) {
	if funk.IsEmpty(issuerURI) {
		return nil, fmt.Errorf("issuer URI is not set")
	}
	config, confErr := fetchOpenIDConfiguration(fmt.Sprintf("%s/%s", issuerURI, DiscoveryPath))
	if confErr != nil {
		return nil, confErr
	}
	if funk.IsEmpty(keyPath) {
		return nil, fmt.Errorf("key path is not set")
	}

	keyFile, readErr := os.ReadFile(keyPath)
	if readErr != nil {
		return nil, readErr
	}

	return &OpenIDConfig{
		IDPConfig: config,
		Key:       keyFile,
	}, nil
}

func NewOpenIDConfigFromKey(issuerURI string, key []byte) (*OpenIDConfig, error) {
	config, confErr := fetchOpenIDConfiguration(fmt.Sprintf("%s/%s", issuerURI, DiscoveryPath))
	if confErr != nil {
		return nil, confErr
	}

	return &OpenIDConfig{
		IDPConfig: config,
		Key:       key,
	}, nil
}

func fetchOpenIDConfiguration(openIDConfigURL string) (*IDPConfiguration, error) {
	resp, err := http.Get(openIDConfigURL)
	if err != nil {
		return nil, err
	}

	defer func(Body io.ReadCloser) {
		closeErr := Body.Close()
		if closeErr != nil {
			log.Errorf("failed to close response body: %s", closeErr)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch OpenID configuration: %s", resp.Status)
	}

	var config IDPConfiguration
	err = json.NewDecoder(resp.Body).Decode(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
