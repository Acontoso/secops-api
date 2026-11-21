package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appcontainer "github.com/Acontoso/soar-api/code/app"
	"github.com/Acontoso/soar-api/code/database"
	"github.com/Acontoso/soar-api/code/middleware"
	"github.com/aws/aws-lambda-go/events"
	ginadapter "github.com/awslabs/aws-lambda-go-api-proxy/gin"
	"github.com/gin-gonic/gin"
)

func testRouter(t *testing.T) *gin.Engine {
	t.Helper()
	for name, value := range map[string]string{
		"AWS_REGION": "us-east-1", "AWS_CONFIG_FILE": os.DevNull, "AWS_SHARED_CREDENTIALS_FILE": os.DevNull,
		"AWS_PROFILE": "", "AWS_DEFAULT_PROFILE": "", "AWS_EC2_METADATA_DISABLED": "true",
		"COGNITO_USER_POOL_ID": "us-east-1_test", "COGNITO_CLIENT_ID": "client", "COGNITO_REQUIRED_SCOPE": "custom/read",
	} {
		t.Setenv(name, value)
	}
	app := &appcontainer.App{Router: gin.New()}
	r := buildRouter(app)
	if r != app.Router {
		t.Fatal("builder changed router ownership")
	}
	return r
}

func requestLogs(t *testing.T, fn func()) (data []byte) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = writer
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() { b, err := io.ReadAll(reader); done <- result{b, err} }()
	defer func() {
		os.Stdout = old
		_ = writer.Close()
		got := <-done
		_ = reader.Close()
		if got.err != nil {
			t.Errorf("read request logs: %v", got.err)
		}
		data = got.data
	}()
	fn()
	return
}

func TestMainStopsOnConfigurationFailure(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(configPath, []byte("[default]\nregion=ap-southeast-2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"AWS_CONFIG_FILE": configPath, "AWS_SHARED_CREDENTIALS_FILE": os.DevNull,
		"AWS_PROFILE": "missing-test-profile", "AWS_DEFAULT_PROFILE": "",
		"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test",
		"AWS_EC2_METADATA_DISABLED": "true",
	} {
		t.Setenv(key, value)
	}
	// Confirm the deterministic stop condition before calling main: this test
	// must never reach either the local listener or the Lambda event loop.
	if _, err := database.NewDynamoDBClient(context.Background()); err == nil {
		t.Fatal("test configuration did not reject the missing profile")
	}
	previousLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	output := requestLogs(t, main)
	if !bytes.Contains(output, []byte("failed to initialize dynamodb client")) {
		t.Fatalf("startup did not report configuration failure: %s", output)
	}
	if bytes.Contains(output, []byte("API application is starting")) {
		t.Fatalf("startup continued after configuration failure: %s", output)
	}
}

func TestRouterComposition(t *testing.T) {
	r := testRouter(t)
	// These test-only endpoints exercise the actual installed middleware.
	r.GET("/panic", func(c *gin.Context) { panic("test panic") })
	r.GET("/context", func(c *gin.Context) {
		if len(c.GetString("request_id")) != 32 {
			t.Error("request ID middleware missing")
		}
		if _, ok := c.Get("logger"); !ok || middleware.GetLogger(c) == nil {
			t.Error("request logger middleware missing")
		}
		c.Status(http.StatusNoContent)
	})
	for _, tc := range []struct {
		method, path string
		status       int
		body         string
	}{
		{http.MethodGet, "/", http.StatusOK, "API is healthy!"},
		{http.MethodGet, "/health", http.StatusOK, "API is healthy!"},
		{http.MethodGet, "/context", http.StatusNoContent, ""},
		{http.MethodGet, "/panic", http.StatusInternalServerError, ""},
		{http.MethodPost, "/api/enrich/anomali", http.StatusUnauthorized, `{"error":"Unauthorized"}`},
		{http.MethodGet, "/unknown", http.StatusNotFound, "404 page not found"},
		{http.MethodPost, "/health", http.StatusNotFound, "404 page not found"},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			output := requestLogs(t, func() { r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil)) })
			if w.Code != tc.status || w.Body.String() != tc.body {
				t.Fatalf("response %d %q", w.Code, w.Body.String())
			}
			var entry middleware.RequestlogEntry
			if err := json.Unmarshal(bytes.TrimSpace(output), &entry); err != nil {
				t.Fatalf("invalid log: %v: %s", err, output)
			}
			if entry.Method != tc.method || entry.Path != tc.path || entry.Status != tc.status || len(entry.RequestID) != 32 {
				t.Fatalf("middleware log: %+v", entry)
			}
		})
	}
}

func TestLambdaAdapterUsesComposedRouter(t *testing.T) {
	r := testRouter(t)
	adapter := ginadapter.New(r)
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/health", "API is healthy!", http.StatusOK},
		{http.MethodGet, "/", "API is healthy!", http.StatusOK},
		{http.MethodPost, "/api/soar/sse/zscaler", `{"error":"Unauthorized"}`, http.StatusUnauthorized},
		{http.MethodGet, "/not-found", "404 page not found", http.StatusNotFound},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			output := requestLogs(t, func() {
				response, err := adapter.ProxyWithContext(context.Background(), events.APIGatewayProxyRequest{
					HTTPMethod: tc.method, Path: tc.path, QueryStringParameters: map[string]string{"value": "a/b"},
					Headers: map[string]string{"User-Agent": "lambda-test"}, RequestContext: events.APIGatewayProxyRequestContext{Identity: events.APIGatewayRequestIdentity{SourceIP: "192.0.2.12"}},
				})
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != tc.status || response.Body != tc.body || response.IsBase64Encoded {
					t.Fatalf("proxy response: %+v", response)
				}
			})
			var entry middleware.RequestlogEntry
			if err := json.Unmarshal(bytes.TrimSpace(output), &entry); err != nil {
				t.Fatal(err)
			}
			if entry.Status != tc.status || entry.Method != tc.method || !strings.HasPrefix(entry.Path, tc.path+"?") || !strings.Contains(entry.Path, "value=a%2Fb") || entry.UserAgent != "lambda-test" {
				t.Fatalf("adapter middleware: %+v", entry)
			}
		})
	}
}
