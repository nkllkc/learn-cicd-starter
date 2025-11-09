package auth

import (
	"testing"
)

func TestAuth(t *testing.T) {
	t.Run("GetAPIKey", func(t *testing.T) {
		t.Run("NoAuthHeader", func(t *testing.T) {
			headers := make(map[string][]string)
			_, err := GetAPIKey(headers)
			if err != ErrNoAuthHeaderIncluded {
				t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
			}
		})
		t.Run("MalformedAuthHeader", func(t *testing.T) {
			headers := make(map[string][]string)
			headers["Authorization"] = []string{"Bearer some_token"}
			_, err := GetAPIKey(headers)
			if err == nil || err.Error() != "malformed authorization header" {
				t.Errorf("expected malformed authorization header error, got %v", err)
			}
		})
		t.Run("ValidAuthHeader", func(t *testing.T) {
			headers := make(map[string][]string)
			headers["Authorization"] = []string{"ApiKey valid_api_key"}
			apiKey, err := GetAPIKey(headers)
			if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			if apiKey != "valid_api_key" {
				t.Errorf("expected api key 'valid_api_key', got %s", apiKey)
			}
		})
	})
}
