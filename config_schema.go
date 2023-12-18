package main

import (
	"net/url"
)

type Schema struct {
	AutheliaURL *url.URL     `koanf:"authelia_url"`
	Storage     string       `koanf:"storage"`
	OAuth2      SchemaOAuth2 `koanf:"oauth2"`
}

type SchemaOAuth2 struct {
	Bearer SchemaOAuth2Bearer `koanf:"bearer"`
}

type SchemaOAuth2Bearer struct {
	ID                      string   `koanf:"id"`
	Secret                  string   `koanf:"secret"`
	PAR                     bool     `koanf:"par"`
	Audience                []string `koanf:"audience"`
	Scope                   []string `koanf:"scope"`
	GrantType               string   `koanf:"grant_type"`
	TokenEndpointAuthMethod string   `koanf:"token_endpoint_auth_method"`
	OfflineAccess           bool     `koanf:"offline_access"`
}
