package store

import (
	"time"
)

type Storage struct {
	// Tokens is a list of relevant tokens for a given client configuration. The key is the client name.
	Tokens map[string]Token `koanf:"tokens" json:"tokens,omitempty" yaml:"tokens,omitempty" toml:"tokens,omitempty"`
}

type Token struct {
	AccessToken  string    `koanf:"access_token" json:"access_token" yaml:"access_token" toml:"access_token"`
	RefreshToken string    `koanf:"refresh_token" json:"refresh_token,omitempty" yaml:"refresh_token,omitempty" toml:"refresh_token,omitempty"`
	IDToken      string    `koanf:"id_token" yaml:"id_token,omitempty" json:"id_token,omitempty" toml:"id_token,omitempty"`
	TokenType    string    `koanf:"token_type" json:"token_type,omitempty" yaml:"token_type,omitempty" toml:"token_type,omitempty"`
	Scope        string    `koanf:"scope" json:"scope,omitempty" yaml:"scope,omitempty" toml:"scope,omitempty"`
	Expiry       time.Time `koanf:"expiry" json:"expiry,omitempty" yaml:"expiry,omitempty" toml:"expiry,omitempty"`
}
