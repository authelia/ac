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

func (config *OAuth2Bearer) Validate() (err error) {
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
