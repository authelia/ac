package config

import (
	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/v2"
)

func Unmarshal(ko *koanf.Koanf, data any) (err error) {
	c := koanf.UnmarshalConf{
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToSliceHookFunc(","),
				mStringToURLHookFunc(),
			),
			Metadata:         nil,
			Result:           data,
			WeaklyTypedInput: true,
		},
	}

	if err = ko.UnmarshalWithConf("", data, c); err != nil {
		return err
	}

	return nil
}
