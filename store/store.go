package store

import (
	"fmt"
	"os"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"

	"authelia.com/tools/ac/config"
)

func Load(path string) (store *Storage, err error) {
	var stat os.FileInfo

	if stat, err = os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			var f *os.File

			if f, err = os.Create(path); err != nil {
				return nil, fmt.Errorf("error validating storage: the path '%s' has an issue: had an error creating the file: %w", path, err)
			}

			if err = f.Close(); err != nil {
				return nil, fmt.Errorf("error validating storage: the path '%s' has an issue: had an error closing the file after creating it: %w", path, err)
			}
		} else {
			return nil, fmt.Errorf("error validating storage: the path '%s' has an issue: had an error reading the file: %w", path, err)
		}
	} else if stat.IsDir() {
		return nil, fmt.Errorf("error validating storage: the path '%s' has an issue: it's a directory instead of a file", path)
	}

	ko := koanf.New(".")

	kpath := file.Provider(path)

	if err = ko.Load(kpath, yaml.Parser()); err != nil {
		return nil, fmt.Errorf("error occurred loading file storage: %w", err)
	}

	store = &Storage{
		Tokens: map[string]Token{},
	}

	if err = config.Unmarshal(ko, store); err != nil {
		return nil, fmt.Errorf("error occurred unmarshalling storage: %w", err)
	}

	return store, nil
}
