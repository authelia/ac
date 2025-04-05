package store

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml"
	"gopkg.in/yaml.v3"
)

func (s *Storage) Save(path string) (err error) {
	var data []byte

	switch ext := filepath.Ext(path); ext {
	case ".yml", ".yaml":
		data, err = yaml.Marshal(s)
	case ".tml", ".toml":
		data, err = toml.Marshal(s)
	default:
		err = fmt.Errorf("extension '%s' for file '%s' is not supported", ext, path)
	}

	if err != nil {
		return fmt.Errorf("error occurred marshalling the updated storage: %w", err)
	}

	var f *os.File

	if f, err = os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600); err != nil {
		return fmt.Errorf("error occurred opening file '%s': %w", path, err)
	}

	defer f.Close()

	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("error occurred writing to file '%s': %w", path, err)
	}

	return nil
}
