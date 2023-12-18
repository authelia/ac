package main

import (
	"fmt"
)

func (config *Schema) validate() (err error) {
	if config.AutheliaURL == nil {
		return fmt.Errorf("error validating configuration: the 'authelia_url' value is required")
	}

	if len(config.Storage) == 0 {
		return fmt.Errorf("error validating configuration: the 'storage' value is required")
	}

	return nil
}

const (
	errFmtRequiredOptionOAuth2Bearer = "error validating configuration: oauth2: bearer: the '%s' value is required"
	errFmtNotKnownOptionOAuth2Bearer = "error validating configuration: oauth2: bearer: the '%s' value of '%s' is not known"
)

func (config *SchemaOAuth2Bearer) validate() (err error) {
	if len(config.ID) == 0 {
		return fmt.Errorf(errFmtRequiredOptionOAuth2Bearer, strID)
	}

	if len(config.Secret) == 0 {
		return fmt.Errorf(errFmtRequiredOptionOAuth2Bearer, strSecret)
	}

	if len(config.Scope) == 0 {
		return fmt.Errorf(errFmtRequiredOptionOAuth2Bearer, strScope)
	}

	switch config.GrantType {
	case "":
		return fmt.Errorf(errFmtRequiredOptionOAuth2Bearer, strGrantType)
	case strAuthorizationCode, strRefreshToken, strClientCredentials:
		break
	default:
		return fmt.Errorf(errFmtNotKnownOptionOAuth2Bearer, strGrantType, config.GrantType)
	}

	switch config.TokenEndpointAuthMethod {
	case "":
		return fmt.Errorf(errFmtRequiredOptionOAuth2Bearer, strTokenEndpointAuthMethod)
	case strClientSecretPost, strClientSecretBasic:
		break
	default:
		return fmt.Errorf(errFmtNotKnownOptionOAuth2Bearer, strTokenEndpointAuthMethod, config.TokenEndpointAuthMethod)
	}

	return nil
}
