package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/gin-gonic/gin"
)

type svcTestRoundTripper func(*http.Request) (*http.Response, error)

func (f svcTestRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := f(r)
	if resp != nil {
		resp.Request = r
	}
	return resp, err
}
func svcTestJSONResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func svcTestLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func svcTestContext(ctx context.Context) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/", nil).WithContext(ctx)
	return c
}
func svcTestAWSConfig(rt http.RoundTripper) aws.Config {
	return aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), Retryer: func() aws.Retryer { return aws.NopRetryer{} }, HTTPClient: &http.Client{Transport: rt}}
}
func svcTestSecrets(t *testing.T, failName string) (*ssm.Client, *kms.Client) {
	t.Helper()
	t.Setenv("SSM_PARAMETER_PREFIX", "/soar-api")
	rt := svcTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || (r.URL.Host != "ssm.us-east-1.amazonaws.com" && r.URL.Host != "kms.us-east-1.amazonaws.com") {
			t.Fatalf("unexpected AWS destination: %s %s", r.Method, r.URL)
		}
		switch r.Header.Get("X-Amz-Target") {
		case "AmazonSSM.GetParameter":
			var p struct {
				Name           string
				WithDecryption bool
			}
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				t.Fatal(err)
			}
			if !p.WithDecryption || !strings.HasPrefix(p.Name, "/soar-api/") {
				t.Fatalf("SSM request: %+v", p)
			}
			if strings.TrimPrefix(p.Name, "/soar-api/") == failName {
				return svcTestJSONResponse(400, `{"__type":"ParameterNotFound","message":"missing secret"}`), nil
			}
			return svcTestJSONResponse(200, fmt.Sprintf(`{"Parameter":{"Value":%q}}`, base64.StdEncoding.EncodeToString([]byte(strings.TrimPrefix(p.Name, "/soar-api/"))))), nil
		case "TrentService.Decrypt":
			var p struct{ CiphertextBlob []byte }
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				t.Fatal(err)
			}
			return svcTestJSONResponse(200, fmt.Sprintf(`{"Plaintext":%q}`, base64.StdEncoding.EncodeToString([]byte("secret-"+string(p.CiphertextBlob))))), nil
		default:
			t.Fatalf("unexpected AWS request: %s %s", r.URL, r.Header.Get("X-Amz-Target"))
			return nil, fmt.Errorf("unexpected AWS request")
		}
	})
	cfg := svcTestAWSConfig(rt)
	return ssm.NewFromConfig(cfg), kms.NewFromConfig(cfg)
}

type svcTestBody struct {
	io.Reader
	closed bool
	err    error
}

func (b *svcTestBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	return b.Reader.Read(p)
}
func (b *svcTestBody) Close() error { b.closed = true; return nil }
func svcTestDefaultTransport(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	old := http.DefaultTransport
	http.DefaultTransport = rt
	t.Cleanup(func() { http.DefaultTransport = old })
}
