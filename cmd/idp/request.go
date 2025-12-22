// Package main contains an example identity provider implementation.
package main

import (
	"bytes"
	"net/http"
)

func newTestRequest(method string, path string, body []byte, pathValues map[string]string) (*http.Request, error) {
	var req, _ = http.NewRequest(method, path, bytes.NewReader(body))

	for k, v := range pathValues {
		req.SetPathValue(k, v)
	}

	return req, nil
}
