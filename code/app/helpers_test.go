package app

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Acontoso/soar-api/code/models"
	"github.com/gin-gonic/gin"
)

func TestBestEffortPersistence(t *testing.T) {
	for _, tt := range []struct {
		name string
		save func(*App, *gin.Context, *slog.Logger)
	}{
		{"SOAR", func(a *App, c *gin.Context, lg *slog.Logger) { a.saveSOARRecord(c, lg, &models.SOARTable{}) }},
		{"IOC", func(a *App, c *gin.Context, lg *slog.Logger) { a.saveIOCRecord(c, lg, &models.IOCTable{}) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
			var logs bytes.Buffer
			tt.save(&App{}, c, slog.New(slog.NewJSONHandler(&logs, nil)))
			if c.Writer.Written() {
				t.Fatal("best-effort persistence failure wrote an HTTP response")
			}
			for _, message := range []string{"dynamodb client is nil", "failed to put item into dynamodb"} {
				if strings.Count(logs.String(), message) != 1 {
					t.Errorf("expected one %q log; got %s", message, logs.String())
				}
			}
		})
	}
}

func TestBindAbuseIPPayloadValid(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
		dst  any
	}{
		{"lookup", `{"ip":"192.0.2.1","incident_id":"test"}`, &models.ClientAbuseIPRequestPayload{}},
		{"manual lookup", `{"ip":"192.0.2.1"}`, &models.ManualLookupIPRequestPayload{}},
		{"manual add", `{"ip":"192.0.2.1","public":true,"abuse_confidence_score":75,"country":"Australia","country_code":"AU","report_count":1,"incident_id":"test"}`, &models.ManualAddAbuseIPPayload{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			if !bindAbuseIPPayload(c, tt.dst) {
				t.Fatal("valid payload rejected")
			}
			if c.Writer.Written() {
				t.Fatal("valid payload wrote an early response")
			}
		})
	}
}

func TestSydneyDate(t *testing.T) {
	for _, tt := range []struct {
		name string
		at   string
		want string
	}{
		{"summer next day", "2026-01-01T13:00:00Z", "02-01-2026"},
		{"winter same day", "2026-07-01T13:00:00Z", "01-07-2026"},
		{"winter next day", "2026-07-01T14:00:00Z", "02-07-2026"},
		{"year boundary", "2025-12-31T13:00:00Z", "01-01-2026"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			at, err := time.Parse(time.RFC3339, tt.at)
			if err != nil {
				t.Fatal(err)
			}
			if got := sydneyDate(at); got != tt.want {
				t.Fatalf("sydneyDate(%v) = %q, want %q", at, got, tt.want)
			}
		})
	}
}

func TestScoreFromInfo(t *testing.T) {
	for _, tt := range []struct {
		name string
		info map[string]interface{}
		want int
	}{
		{"nil", nil, 0},
		{"missing", map[string]interface{}{}, 0},
		{"integer", map[string]interface{}{"Score": 75}, 75},
		{"float", map[string]interface{}{"Score": 75.9}, 75},
		{"negative float", map[string]interface{}{"Score": -2.9}, -2},
		{"string", map[string]interface{}{"Score": "75"}, 0},
		{"int64", map[string]interface{}{"Score": int64(75)}, 0},
		{"float32", map[string]interface{}{"Score": float32(75)}, 0},
		{"null", map[string]interface{}{"Score": nil}, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := scoreFromInfo(tt.info); got != tt.want {
				t.Fatalf("scoreFromInfo(%v) = %d, want %d", tt.info, got, tt.want)
			}
		})
	}
}
