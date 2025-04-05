package store

import (
	"time"
)

type Storage struct {
	Tokens map[string]Token
}

type Token struct {
	AccessToken  string    `koanf:"access_token" yaml:"access_token" json:"access_token"`
	RefreshToken string    `koanf:"refresh_token" yaml:"refresh_token,omitempty" json:"refresh_token,omitempty"`
	IDToken      string    `koanf:"id_token" yaml:"id_token,omitempty" json:"id_token,omitempty"`
	TokenType    string    `koanf:"token_type" yaml:"token_type,omitempty" json:"token_type,omitempty"`
	Scope        string    `koanf:"scope" yaml:"scope,omitempty" json:"scope,omitempty"`
	Expiry       time.Time `koanf:"expiry" yaml:"expiry,omitempty" json:"expiry,omitempty"`
}
