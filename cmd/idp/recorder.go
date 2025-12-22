// Package main contains an example identity provider implementation.
package main

import (
	"bytes"
	"net/http"
)

// responseRecorder is a simple http.ResponseWriter that captures the status code
// and body of a response.
type responseRecorder struct {
	Code      int
	Body      *bytes.Buffer
	headerMap http.Header
}

// newResponseRecorder creates a new responseRecorder.
func newResponseRecorder() *responseRecorder {
	return &responseRecorder{
		Code:      http.StatusOK,
		Body:      new(bytes.Buffer),
		headerMap: make(http.Header),
	}
}

// Header returns the header map.
func (r *responseRecorder) Header() http.Header {
	return r.headerMap
}

// WriteHeader captures the status code.
func (r *responseRecorder) WriteHeader(code int) {
	r.Code = code
}

// Write captures the response body.
func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.Body.Write(b)
}

// IsSuccess returns true if the response code is a 2xx status code.
func (r *responseRecorder) IsSuccess() bool {
	return r.Code >= 200 && r.Code < 300
}
