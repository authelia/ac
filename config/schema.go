package config

import (
	"net/url"
)

type Configuration struct {
	AutheliaURL *url.URL `koanf:"authelia_url"`
	Storage     string   `koanf:"storage"`
	OAuth2      OAuth2   `koanf:"oauth2"`
	Server      Server   `koanf:"server"`
}

type Server struct {
	Port uint16 `koanf:"port"`
}

type OAuth2 struct {
	Bearer OAuth2Bearer `koanf:"bearer"`
}

type OAuth2Bearer struct {
	ID                      string   `koanf:"id"`
	Secret                  string   `koanf:"secret"`
	PAR                     bool     `koanf:"par"`
	Audience                []string `koanf:"audience"`
	Scope                   []string `koanf:"scope"`
	GrantType               string   `koanf:"grant_type"`
	TokenEndpointAuthMethod string   `koanf:"token_endpoint_auth_method"`
	OfflineAccess           bool     `koanf:"offline_access"`
}
