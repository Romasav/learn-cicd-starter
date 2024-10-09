package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers    http.Header
		wantAPIKey string
		wantErr    error
	}{
		"No Authorization Header": {
			headers: http.Header{},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"Malformed Authorization Header - Missing ApiKey Prefix": {
			headers: http.Header{
				"Authorization": []string{"Bearer somekey"},
			},
			wantErr: errors.New("malformed authorization header"),
		},
		"Malformed Authorization Header - Missing Key": {
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantErr: errors.New("malformed authorization header"),
		},
		"Valid Authorization Header": {
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			wantAPIKey: "my-secret-key",
			wantErr:    nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)
			if tt.wantErr != nil {
				if err == nil || err.Error() != tt.wantErr.Error() {
					t.Errorf("Expected error '%v', got '%v'", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if apiKey != tt.wantAPIKey {
				t.Errorf("Expected API key '%s', got '%s'", tt.wantAPIKey, apiKey)
			}
		})
	}
}
