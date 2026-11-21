package app

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestStrictBindJSONCharacterization pins the observable behaviour of the
// shared request decoder: it rejects unknown fields, only accepts one JSON
// value, and reports malformed or empty bodies to the caller.
func TestStrictBindJSONCharacterization(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type payload struct {
		IP         string `json:"ip"`
		IncidentID string `json:"incident_id"`
	}

	tests := []struct {
		name         string
		body         string
		wantErr      bool
		wantErrIs    error
		wantContains string
		wantExactErr string
		wantIP       string
		wantIncident string
	}{
		{
			name:         "valid single object",
			body:         `{"ip":"1.2.3.4","incident_id":"inc-1"}`,
			wantErr:      false,
			wantIP:       "1.2.3.4",
			wantIncident: "inc-1",
		},
		{
			name:      "empty body",
			body:      ``,
			wantErr:   true,
			wantErrIs: io.EOF,
		},
		{
			name:         "malformed truncated object",
			body:         `{"ip":`,
			wantErr:      true,
			wantContains: "unexpected",
		},
		{
			name:         "unknown field",
			body:         `{"ip":"1.2.3.4","incident_id":"inc-1","unexpected":true}`,
			wantErr:      true,
			wantContains: `unknown field "unexpected"`,
		},
		{
			name:         "trailing empty object",
			body:         `{"ip":"1.2.3.4","incident_id":"inc-1"}{}`,
			wantErr:      true,
			wantExactErr: "payload must contain only one JSON object",
		},
		{
			name:         "trailing second object",
			body:         `{"ip":"1.2.3.4","incident_id":"inc-1"}{"ip":"5.6.7.8"}`,
			wantErr:      true,
			wantContains: `unknown field "ip"`,
		},
		{
			name:         "trailing garbage",
			body:         `{"ip":"1.2.3.4","incident_id":"inc-1"} trailing`,
			wantErr:      true,
			wantContains: "invalid character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(tt.body))

			var got payload
			err := strictBindJSON(c, &got)

			if !tt.wantErr {
				if err != nil {
					t.Fatalf("strictBindJSON() error = %v, want nil", err)
				}
				if got.IP != tt.wantIP {
					t.Errorf("decoded IP = %q, want %q", got.IP, tt.wantIP)
				}
				if got.IncidentID != tt.wantIncident {
					t.Errorf("decoded IncidentID = %q, want %q", got.IncidentID, tt.wantIncident)
				}
				return
			}

			if err == nil {
				t.Fatalf("strictBindJSON() error = nil, want non-nil")
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Errorf("strictBindJSON() error = %v, want errors.Is %v", err, tt.wantErrIs)
			}
			if tt.wantExactErr != "" && err.Error() != tt.wantExactErr {
				t.Errorf("strictBindJSON() error = %q, want exact %q", err.Error(), tt.wantExactErr)
			}
			if tt.wantContains != "" && !strings.Contains(err.Error(), tt.wantContains) {
				t.Errorf("strictBindJSON() error = %q, want substring %q", err.Error(), tt.wantContains)
			}
		})
	}
}
