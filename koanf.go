package main

import (
	"github.com/knadh/koanf/v2"
	"github.com/mitchellh/mapstructure"
)

func koUnmarshal(ko *koanf.Koanf, data any) (err error) {
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
