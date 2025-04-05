package store

import (
	"fmt"
	"os"
	"path/filepath"

	"authelia.com/tools/ac/utilities"
)

func (s *Storage) Save(path string) (err error) {
	var data []byte

	if data, err = utilities.AutoMarshal(s, filepath.Ext(path)); err != nil {
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
