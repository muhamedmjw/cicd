package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "Valid API key",
			headers:     http.Header{"Authorization": {"ApiKey my-secret-key"}},
			expectedKey: "my-secret-key",
			expectedErr: nil,
		},
		{
			name:        "No Authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Malformed Authorization header",
			headers:     http.Header{"Authorization": {"InvalidHeader my-secret-key"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "Empty API key",
			headers:     http.Header{"Authorization": {"ApiKey "}},
			expectedKey: "",
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Check the key
			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			// Check the error
			if (err == nil && tt.expectedErr != nil) || (err != nil && tt.expectedErr == nil) || (err != nil && tt.expectedErr != nil && !strings.Contains(err.Error(), tt.expectedErr.Error())) {
				t.Errorf("expected error %q, got %q", tt.expectedErr, err)
			}
		})
	}
}
