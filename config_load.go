package main

import (
	"fmt"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"
)

func loadConfig(path string, flags *pflag.FlagSet, flagsPrefix string) (config *Schema, err error) {
	ko := koanf.New(".")

	kdefault := confmap.Provider(defaultConfig, ".")

	kpath := file.Provider(path)

	kflags := posflag.ProviderWithFlag(flags, ".", ko, configCallbackPosFlag(flagsPrefix))

	if err = ko.Load(kdefault, nil); err != nil {
		return nil, fmt.Errorf("error occurred loading default configuration: %w", err)
	}

	if err = ko.Load(kpath, yaml.Parser()); err != nil {
		return nil, fmt.Errorf("error occurred loading file configuration: %w", err)
	}

	if err = ko.Load(kflags, nil); err != nil {
		return nil, fmt.Errorf("error occurred loading flags configuration: %w", err)
	}

	config = &Schema{}

	if err = koUnmarshal(ko, config); err != nil {
		return nil, fmt.Errorf("error occurred unmarshalling configuration: %w", err)
	}

	return config, nil
}

var (
	defaultConfig = map[string]any{
		"storage": "storage.yml",
	}
)
