package utilities

import (
	"encoding/json"
	"fmt"

	"github.com/pelletier/go-toml"
	"gopkg.in/yaml.v3"

	"authelia.com/tools/ac/consts"
)

func AutoMarshal(v any, ext string) (data []byte, err error) {
	switch ext {
	case consts.FileTypeYAML, consts.FileTypeAltYAML:
		data, err = yaml.Marshal(v)
	case consts.FileTypeTOML, consts.FileTypeAltTOML:
		data, err = toml.Marshal(v)
	case consts.FileTypeJSON:
		data, err = json.MarshalIndent(v, "", "  ")
	default:
		err = fmt.Errorf("extension '%s' is not supported", ext)
	}

	return
}
