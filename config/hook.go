package config

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/pflag"
)

func mStringToURLHookFunc() mapstructure.DecodeHookFuncType {
	return func(f reflect.Type, t reflect.Type, data any) (value any, err error) {
		var ptr bool

		if f.Kind() != reflect.String {
			return data, nil
		}

		prefixType := ""

		if t.Kind() == reflect.Ptr {
			ptr = true
			prefixType = "*"
		}

		expectedType := reflect.TypeOf(URL{})

		if ptr && t.Elem() != expectedType {
			return data, nil
		} else if !ptr && t != expectedType {
			return data, nil
		}

		dataStr := data.(string)

		var result *url.URL

		if dataStr != "" {
			if result, err = url.Parse(dataStr); err != nil {
				return nil, fmt.Errorf("could not decode '%s' to a %s%s: %w", dataStr, prefixType, expectedType, err)
			}
		}

		if ptr {
			return (*URL)(result), nil
		}

		if result == nil {
			return URL{}, nil
		}

		return (URL)(*result), nil
	}
}

func configCallbackPosFlag(prefix string) func(flag *pflag.Flag) (key string, value any) {
	return func(flag *pflag.Flag) (key string, value any) {
		if !flag.Changed {
			return "", nil
		}

		var parts []string

		if prefix != "" {
			parts = append(parts, prefix)
		}

		parts = append(parts, strings.ReplaceAll(flag.Name, "-", "_"))

		key = strings.Join(parts, ".")

		return key, flag.Value.String()
	}
}
