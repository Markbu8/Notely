package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		wantKey    string
		wantErr    error
		wantErrMsg string
	}{
		{
			name:    "valid key",
			header:  "ApiKey my-secret-key",
			wantKey: "my-secret-key",
		},
		{
			name:    "no header",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:       "wrong scheme",
			header:     "Bearer my-secret-key",
			wantErrMsg: "malformed authorization header",
		},
		{
			name:       "missing key value",
			header:     "ApiKey",
			wantErrMsg: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.header != "" {
				headers.Set("Authorization", tt.header)
			}

			key, err := GetAPIKey(headers)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got err %v, want %v", err, tt.wantErr)
				}
			} else if tt.wantErrMsg != "" {
				if err == nil || err.Error() != tt.wantErrMsg {
					t.Errorf("got err %v, want %q", err, tt.wantErrMsg)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if key != tt.wantKey {
				t.Errorf("got key %q, want %q", key, tt.wantKey)
			}
		})
	}
}
