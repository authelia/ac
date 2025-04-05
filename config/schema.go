package config

import (
	"net/url"
)

type Configuration struct {
	AutheliaURL *URL   `koanf:"authelia_url" json:"authelia_url,omitempty" yaml:"authelia_url,omitempty" toml:"authelia_url,omitempty"`
	Storage     string `koanf:"storage" json:"storage,omitempty" yaml:"storage,omitempty" toml:"storage,omitempty"`
	OAuth2      OAuth2 `koanf:"oauth2" json:"oauth2" yaml:"oauth2" toml:"oauth2"`
	Server      Server `koanf:"server" json:"server" yaml:"server" toml:"server"`
}

type Server struct {
	Port uint16 `koanf:"port" json:"port" yaml:"port" toml:"port"`
}

type OAuth2 struct {
	DefaultClient string        `koanf:"default_client" json:"default_client,omitempty" yaml:"default_client,omitempty" toml:"default_client,omitempty"`
	Clients       OAuth2Clients `koanf:"clients" json:"clients" yaml:"clients" toml:"clients"`
}

type OAuth2Clients map[string]OAuth2Client

type OAuth2Client struct {
	ID                      string   `koanf:"id" json:"id" yaml:"id" toml:"id"`
	Secret                  string   `koanf:"secret" json:"secret" yaml:"secret" toml:"secret"`
	PAR                     bool     `koanf:"par" json:"par" yaml:"par" toml:"par"`
	Audience                []string `koanf:"audience" json:"audience" yaml:"audience" toml:"audience"`
	Scope                   []string `koanf:"scope" json:"scope" yaml:"scope" toml:"scope"`
	GrantType               string   `koanf:"grant_type" json:"grant_type" yaml:"grant_type" toml:"grant_type"`
	TokenEndpointAuthMethod string   `koanf:"token_endpoint_auth_method" json:"token_endpoint_auth_method" yaml:"token_endpoint_auth_method" toml:"token_endpoint_auth_method"`
	OfflineAccess           bool     `koanf:"offline_access" json:"offline_access" yaml:"offline_access" toml:"offline_access"`
}

func NewURL(in *url.URL) *URL {
	return (*URL)(in)
}

type URL url.URL

func (u *URL) MarshalText() (text []byte, err error) {
	v := (*url.URL)(u)

	return []byte(v.String()), nil
}
