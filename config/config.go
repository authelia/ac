package config

import (
	"fmt"
	"path/filepath"

	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"

	"authelia.com/tools/ac/consts"
)

// Load the configuration.
func Load(paths []string, flags *pflag.FlagSet, flagsPrefix string) (config *Configuration, err error) {
	ko := koanf.New(".")

	kdefault := confmap.Provider(defaultConfig, ".")

	if err = ko.Load(kdefault, nil); err != nil {
		return nil, fmt.Errorf("error occurred loading default configuration: %w", err)
	}

	for _, path := range paths {
		provider := file.Provider(path)

		switch ext := filepath.Ext(path); ext {
		case consts.FileTypeYAML, consts.FileTypeAltYAML, consts.FileTypeJSON:
			if err = ko.Load(provider, yaml.Parser()); err != nil {
				return nil, fmt.Errorf("error occurred loading file configuration: %w", err)
			}
		case consts.FileTypeTOML, consts.FileTypeAltTOML:
			if err = ko.Load(provider, toml.Parser()); err != nil {
				return nil, fmt.Errorf("error occurred loading file configuration: %w", err)
			}
		default:
			return nil, fmt.Errorf("error occurred loading file configuration: extension '%s' for file '%s' is not supported", ext, path)
		}
	}

	kflags := posflag.ProviderWithFlag(flags, ".", ko, configCallbackPosFlag(flagsPrefix))

	if err = ko.Load(kflags, nil); err != nil {
		return nil, fmt.Errorf("error occurred loading flags configuration: %w", err)
	}

	config = &Configuration{}

	if err = Unmarshal(ko, config); err != nil {
		return nil, fmt.Errorf("error occurred unmarshalling configuration: %w", err)
	}

	return config, nil
}

var (
	defaultConfig = map[string]any{
		"server.port": 9019,
		"storage":     "storage.yml",
	}
)
