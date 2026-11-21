package app

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestHandlersEarlyReturnCharacterization exercises only the request
// deserialisation and validation early-return paths of every HTTP handler.
// Every App dependency is nil, so a test reaching AWS/JWKS/HTTP code would
// either panic or attempt a network call; these cases must return first.
func TestHandlersEarlyReturnCharacterization(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const (
		malformedBody = `{"ip":`
		// encoding/json's decoder reports a truncated value as "unexpected EOF".
		malformedAbuseJSON = `{"Error, failed to deserialise into JSON":"unexpected EOF"}`
		fixedMalformedJSON = `{"Error":"Payload failed to deserialise into JSON"}`
		invalidBody        = `{}`
	)

	type handlerCase struct {
		name                string
		handler             func(*App) gin.HandlerFunc
		wantMalformedStatus int
		wantMalformedJSON   string
		wantMalformedLog    string
		wantInvalidStatus   int
		wantInvalidJSON     string
		wantInvalidLog      string
	}

	cases := []handlerCase{
		{
			name:                "AnomaliLookup",
			handler:             func(a *App) gin.HandlerFunc { return a.AnomaliLookup },
			wantMalformedStatus: http.StatusBadRequest,
			wantMalformedJSON:   fixedMalformedJSON,
			wantMalformedLog:    "failed to deserialise into JSON",
			wantInvalidStatus:   http.StatusBadRequest,
			wantInvalidJSON:     `{"error":"Validation of Anomali payload failed"}`,
			wantInvalidLog:      "Validation of Anomali payload failed",
		},
		{
			name:                "CABlock",
			handler:             func(a *App) gin.HandlerFunc { return a.CABlock },
			wantMalformedStatus: http.StatusBadRequest,
			wantMalformedJSON:   fixedMalformedJSON,
			wantMalformedLog:    "failed to deserialise into JSON",
			wantInvalidStatus:   http.StatusBadRequest,
			wantInvalidJSON:     `{"error":"Validation of SSE IOC block payload failed"}`,
			wantInvalidLog:      "Validation of SSE payload failed",
		},
		{
			name:                "DATPBlock",
			handler:             func(a *App) gin.HandlerFunc { return a.DATPBlock },
			wantMalformedStatus: http.StatusBadRequest,
			wantMalformedJSON:   fixedMalformedJSON,
			wantMalformedLog:    "failed to deserialise into JSON",
			wantInvalidStatus:   http.StatusBadRequest,
			wantInvalidJSON:     `{"error":"Validation of SSE IOC block payload failed"}`,
			wantInvalidLog:      "Validation of SSE payload failed",
		},
		{
			name:                "IPLookup",
			handler:             func(a *App) gin.HandlerFunc { return a.IPLookup },
			wantMalformedStatus: http.StatusBadRequest,
			wantMalformedJSON:   malformedAbuseJSON,
			// IPLookup does not log the deserialisation failure.
			wantMalformedLog:  "",
			wantInvalidStatus: http.StatusBadRequest,
			wantInvalidJSON:   `{"details":"Key: 'ClientAbuseIPRequestPayload.IP' Error:Field validation for 'IP' failed on the 'required' tag\nKey: 'ClientAbuseIPRequestPayload.IncidentID' Error:Field validation for 'IncidentID' failed on the 'required' tag","error":"Validation of AbuseIP payload failed"}`,
			// IPLookup does not log the validation failure either.
			wantInvalidLog: "",
		},
		{
			name:                "ManualIPLookup",
			handler:             func(a *App) gin.HandlerFunc { return a.ManualIPLookup },
			wantMalformedStatus: http.StatusBadRequest,
			wantMalformedJSON:   malformedAbuseJSON,
			wantMalformedLog:    "",
			wantInvalidStatus:   http.StatusBadRequest,
			wantInvalidJSON:     `{"details":"Key: 'ManualLookupIPRequestPayload.IP' Error:Field validation for 'IP' failed on the 'required' tag","error":"Validation of AbuseIP payload failed"}`,
			wantInvalidLog:      "",
		},
		{
			name:                "ManualPutAbuseIP",
			handler:             func(a *App) gin.HandlerFunc { return a.ManualPutAbuseIP },
			wantMalformedStatus: http.StatusBadRequest,
			wantMalformedJSON:   malformedAbuseJSON,
			wantMalformedLog:    "",
			wantInvalidStatus:   http.StatusBadRequest,
			wantInvalidJSON:     `{"details":"Key: 'ManualAddAbuseIPPayload.IP' Error:Field validation for 'IP' failed on the 'required' tag\nKey: 'ManualAddAbuseIPPayload.Public' Error:Field validation for 'Public' failed on the 'required' tag\nKey: 'ManualAddAbuseIPPayload.AbuseConfidenceScore' Error:Field validation for 'AbuseConfidenceScore' failed on the 'required' tag\nKey: 'ManualAddAbuseIPPayload.Country' Error:Field validation for 'Country' failed on the 'required' tag\nKey: 'ManualAddAbuseIPPayload.CountryCode' Error:Field validation for 'CountryCode' failed on the 'required' tag\nKey: 'ManualAddAbuseIPPayload.ReportCount' Error:Field validation for 'ReportCount' failed on the 'required' tag\nKey: 'ManualAddAbuseIPPayload.IncidentID' Error:Field validation for 'IncidentID' failed on the 'required' tag","error":"Validation of AbuseIP payload failed"}`,
			wantInvalidLog:      "",
		},
		{
			name:                "RecordedFutureSOAR",
			handler:             func(a *App) gin.HandlerFunc { return a.RecordedFutureSOAR },
			wantMalformedStatus: http.StatusBadRequest,
			wantMalformedJSON:   fixedMalformedJSON,
			wantMalformedLog:    "failed to deserialise into JSON",
			wantInvalidStatus:   http.StatusBadRequest,
			wantInvalidJSON:     `{"error":"Validation of Recorded Future SOAR payload failed"}`,
			wantInvalidLog:      "Validation of Recorded Future SOAR payload failed",
		},
		{
			name:                "SSEBlock",
			handler:             func(a *App) gin.HandlerFunc { return a.SSEBlock },
			wantMalformedStatus: http.StatusBadRequest,
			wantMalformedJSON:   fixedMalformedJSON,
			wantMalformedLog:    "failed to deserialise into JSON",
			wantInvalidStatus:   http.StatusBadRequest,
			wantInvalidJSON:     `{"error":"Validation of SSE IOC block payload failed"}`,
			wantInvalidLog:      "Validation of SSE payload failed",
		},
		{
			name:                "CloudflareBlock",
			handler:             func(a *App) gin.HandlerFunc { return a.CloudflareBlock },
			wantMalformedStatus: http.StatusBadRequest,
			wantMalformedJSON:   fixedMalformedJSON,
			wantMalformedLog:    "failed to deserialise into JSON",
			wantInvalidStatus:   http.StatusBadRequest,
			wantInvalidJSON:     `{"error":"Validation of Cloudflare IOC block payload failed"}`,
			wantInvalidLog:      "Validation of Cloudflare payload failed",
		},
	}

	run := func(t *testing.T, h gin.HandlerFunc, body string, wantStatus int, wantJSON, wantLog string) {
		t.Helper()
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")

		var logs bytes.Buffer
		c.Set("logger", slog.New(slog.NewJSONHandler(&logs, nil)))

		h(c)

		if rec.Code != wantStatus {
			t.Errorf("status = %d, want %d", rec.Code, wantStatus)
		}
		if got := rec.Body.String(); got != wantJSON {
			t.Errorf("body = %s, want %s", got, wantJSON)
		}
		if wantLog != "" && !strings.Contains(logs.String(), wantLog) {
			t.Errorf("logs = %s, want substring %q", logs.String(), wantLog)
		}
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name+"/malformed", func(t *testing.T) {
			app := &App{}
			run(t, tc.handler(app), malformedBody, tc.wantMalformedStatus, tc.wantMalformedJSON, tc.wantMalformedLog)
		})
		t.Run(tc.name+"/validation", func(t *testing.T) {
			app := &App{}
			run(t, tc.handler(app), invalidBody, tc.wantInvalidStatus, tc.wantInvalidJSON, tc.wantInvalidLog)
		})
	}
}
