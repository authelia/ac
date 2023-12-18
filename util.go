package main

import (
	"crypto/rand"
	"fmt"
)

func getRandomBytes(n int, charset []byte) (data []byte, err error) {
	data = make([]byte, n)

	if _, err = rand.Read(data); err != nil {
		return nil, fmt.Errorf("error occurred reading random data: %w", err)
	}

	t := len(charset)

	if t > 0 {
		for i := 0; i < n; i++ {
			data[i] = charset[data[i]%byte(t)]
		}
	}

	return data, nil
}

var (
	charsetRFC3986Unreserved = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
)
