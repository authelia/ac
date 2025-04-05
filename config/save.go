package config

import (
	"fmt"
	"os"
	"path/filepath"

	"authelia.com/tools/ac/utilities"
)

func (config *Configuration) Save(path string) (err error) {
	var data []byte

	if data, err = utilities.AutoMarshal(config, filepath.Ext(path)); err != nil {
		return fmt.Errorf("error occurred marshalling the updated storage: %w", err)
	}

	var f *os.File

	if f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640); err != nil {
		return err
	}

	defer f.Close()

	if _, err = f.Write(data); err != nil {
		return err
	}

	return nil
}
