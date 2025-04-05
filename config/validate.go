package config

import (
	"fmt"

	"authelia.com/tools/ac/consts"
)

func (config *Configuration) Validate() (err error) {
	if config.AutheliaURL == nil {
		return fmt.Errorf("error validating configuration: the 'authelia_url' value is required")
	}

	if len(config.Storage) == 0 {
		return fmt.Errorf("error validating configuration: the 'storage' value is required")
	}

	return nil
}

func (config *OAuth2) Validate() (err error) {
	if err = config.Clients.Validate(); err != nil {
		return err
	}

	if config.DefaultClient != "" {
		if _, ok := config.Clients[config.DefaultClient]; !ok {
			return fmt.Errorf("error validating configuration: the default client '%s' does not exist", config.DefaultClient)
		}
	}
	
	return nil
}

func (config OAuth2Clients) Validate() (err error) {
	for name, client := range config {
		if err = client.Validate(); err != nil {
			return fmt.Errorf("error validating configuration: oauth2: clients: %s: %v", name, err)
		}
	}

	return nil
}

func (config *OAuth2Client) Validate() (err error) {
	if len(config.ID) == 0 {
		return fmt.Errorf(errFmtRequiredOptionOAuth2Bearer, consts.ID)
	}

	if len(config.Secret) == 0 {
		return fmt.Errorf(errFmtRequiredOptionOAuth2Bearer, consts.Secret)
	}

	if len(config.Scope) == 0 {
		return fmt.Errorf(errFmtRequiredOptionOAuth2Bearer, consts.Scope)
	}

	switch config.GrantType {
	case "":
		return fmt.Errorf(errFmtRequiredOptionOAuth2Bearer, consts.GrantType)
	case consts.AuthorizationCode, consts.RefreshToken, consts.ClientCredentials:
		break
	default:
		return fmt.Errorf(errFmtNotKnownOptionOAuth2Bearer, consts.GrantType, config.GrantType)
	}

	switch config.TokenEndpointAuthMethod {
	case "":
		return fmt.Errorf(errFmtRequiredOptionOAuth2Bearer, consts.TokenEndpointAuthMethod)
	case consts.ClientSecretPost, consts.ClientSecretBasic:
		break
	default:
		return fmt.Errorf(errFmtNotKnownOptionOAuth2Bearer, consts.TokenEndpointAuthMethod, config.TokenEndpointAuthMethod)
	}

	return nil
}
