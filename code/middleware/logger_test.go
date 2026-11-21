package middleware

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// Drain concurrently so a full pipe can never block a request. The defer also
// restores stdout and joins the reader if the callback calls Fatal or panics.
func captureStdout(t *testing.T, fn func()) (output []byte) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	type result struct {
		data []byte
		err  error
	}
	drained := make(chan result, 1)
	go func() { data, err := io.ReadAll(reader); drained <- result{data, err} }()
	defer func() {
		os.Stdout = original
		_ = writer.Close()
		got := <-drained
		_ = reader.Close()
		if got.err != nil {
			t.Errorf("read logs: %v", got.err)
		}
		output = got.data
	}()
	fn()
	return
}

func TestJSONLoggerRequestContract(t *testing.T) {
	r := gin.New()
	r.Use(JSONLogger())
	var ids []string
	r.POST("/resource", func(c *gin.Context) {
		id := c.GetString("request_id")
		if _, err := hex.DecodeString(id); err != nil || len(id) != 32 {
			t.Errorf("invalid request ID: %q", id)
		}
		ids = append(ids, id)
		if GetLogger(c) == slog.Default() {
			t.Error("missing request logger")
		}
		if c.Query("user") == "yes" {
			c.Set("username", "caller")
			_ = c.Error(errors.New("private failure"))
			_ = c.Error(errors.New("public failure")).SetType(gin.ErrorTypePublic)
		}
		c.String(http.StatusCreated, "created")
	})
	before := time.Now()
	output := captureStdout(t, func() {
		for _, path := range []string{"/resource?user=yes&value=a%2Fb", "/resource"} {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			req.RemoteAddr = "192.0.2.10:4567"
			req.Header.Set("User-Agent", "logger-test/1")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusCreated || w.Body.String() != "created" {
				t.Errorf("response = %d %s", w.Code, w.Body.String())
			}
		}
	})
	after := time.Now()
	lines := bytes.Split(bytes.TrimSpace(output), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("got %d log lines: %s", len(lines), output)
	}
	for i, line := range lines {
		var entry RequestlogEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatal(err)
		}
		at, err := time.Parse(time.RFC3339Nano, entry.Time)
		if err != nil || at.Before(before) || at.After(after) || entry.LatencyMS < 0 {
			t.Errorf("invalid timing: %+v (%v)", entry, err)
		}
		if entry.RequestID != ids[i] || entry.ClientIP != "192.0.2.10" || entry.Method != http.MethodPost || entry.Status != http.StatusCreated || entry.Size != len("created") || entry.UserAgent != "logger-test/1" {
			t.Errorf("request fields: %+v", entry)
		}
		if i == 0 {
			if entry.Path != "/resource?user=yes&value=a%2Fb" || entry.Client != "caller" || !strings.Contains(entry.Error, "private failure") || strings.Contains(entry.Error, "public failure") {
				t.Errorf("user/query/error fields: %+v", entry)
			}
		} else {
			var fields map[string]any
			if err := json.Unmarshal(line, &fields); err != nil {
				t.Fatal(err)
			}
			if entry.Path != "/resource" || entry.Client != "" || entry.Error != "" {
				t.Errorf("anonymous fields: %+v", entry)
			}
			if _, ok := fields["user_id"]; ok {
				t.Error("empty user_id was not omitted")
			}
			if _, ok := fields["error"]; ok {
				t.Error("empty error was not omitted")
			}
		}
	}
	if ids[0] == ids[1] {
		t.Error("request IDs reused")
	}
}

func TestGetLoggerFallbacks(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if got := GetLogger(c); got != slog.Default() {
		t.Error("missing logger should use default")
	}
	c.Set("logger", "not a logger")
	if got := GetLogger(c); got != slog.Default() {
		t.Error("wrong-type logger should use default")
	}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	c.Set("logger", logger)
	if got := GetLogger(c); got != logger {
		t.Error("request logger was not retained")
	}
}

func TestJSONLoggerAbort(t *testing.T) {
	r := gin.New()
	r.Use(JSONLogger(), func(c *gin.Context) { c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"}) })
	r.GET("/protected", func(c *gin.Context) { t.Error("aborted handler ran") })
	output := captureStdout(t, func() { r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/protected", nil)) })
	var entry RequestlogEntry
	if err := json.Unmarshal(bytes.TrimSpace(output), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Status != http.StatusUnauthorized || entry.Size != len(`{"error":"Unauthorized"}`) || entry.Client != "" {
		t.Fatalf("aborted log: %+v", entry)
	}
}
