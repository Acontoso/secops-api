package services

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/gin-gonic/gin"
)

func TestEnrichmentPayload(t *testing.T) {
	for _, tt := range []struct {
		kind string
		want string
	}{
		{"IPv4", `{"ip":["ioc"],"domain":null,"hash":null}`},
		{"IPv6", `{"ip":["ioc"],"domain":null,"hash":null}`},
		{"Domain", `{"ip":null,"domain":["ioc"],"hash":null}`},
		{"MD5", `{"ip":null,"domain":null,"hash":["ioc"]}`},
		{"SHA1", `{"ip":null,"domain":null,"hash":["ioc"]}`},
		{"SHA256", `{"ip":null,"domain":null,"hash":["ioc"]}`},
		{"unsupported", ""},
	} {
		t.Run(tt.kind, func(t *testing.T) {
			got, err := enrichmentPayload("ioc", tt.kind)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("payload = %s, want %s", got, tt.want)
			}
			if tt.kind == "unsupported" && got != nil {
				t.Fatalf("unsupported type produced non-nil body: %v", got)
			}
		})
	}
}

// TestRecordedFutureTypes exercises the real POST workflow for every supported
// IOC category and asserts the exact request contract.
func TestRecordedFutureTypes(t *testing.T) {
	for _, tc := range []struct{ ioc, kind, body string }{
		{"1.2.3.4", "IPv4", `{"ip":["1.2.3.4"],"domain":null,"hash":null}`},
		{"2001:db8::1", "IPv6", `{"ip":["2001:db8::1"],"domain":null,"hash":null}`},
		{"example.org", "Domain", `{"ip":null,"domain":["example.org"],"hash":null}`},
		{"d41d8cd98f00b204e9800998ecf8427e", "MD5", `{"ip":null,"domain":null,"hash":["d41d8cd98f00b204e9800998ecf8427e"]}`},
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", "SHA1", `{"ip":null,"domain":null,"hash":["da39a3ee5e6b4b0d3255bfef95601890afd80709"]}`},
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256", `{"ip":null,"domain":null,"hash":["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]}`},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			s, k := svcTestSecrets(t, "")
			h := &http.Client{Transport: svcTestRoundTripper(func(r *http.Request) (*http.Response, error) {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				if r.Method != http.MethodPost || r.URL.Host != "offline.invalid" || r.URL.Path != "/custom" {
					t.Fatalf("request = %s %s", r.Method, r.URL)
				}
				if string(raw) != tc.body {
					t.Fatalf("payload = %s, want %s", raw, tc.body)
				}
				if r.Header.Get("X-RFToken") != "secret-recorded_future_api" || r.Header.Get("accept") != "application/json" || r.Header.Get("content-type") != "application/json" {
					t.Fatalf("headers = %v", r.Header)
				}
				return svcTestJSONResponse(200, `{"data":{"results":[{"risk":{"score":93}}]}}`), nil
			})}
			got, err := (&FutureClient{HTTP: h, Timeout: time.Second, BaseURL: "https://offline.invalid/custom"}).GetRecordedFutureEnrichment(svcTestContext(context.Background()), tc.ioc, s, k, svcTestLogger())
			if err != nil || got != 93 {
				t.Fatalf("got %d, %v; want 93, nil", got, err)
			}
		})
	}
}

func TestRecordedFutureErrorContracts(t *testing.T) {
	svcLookupContracts(t, func(c *gin.Context, h *http.Client, d time.Duration, u string, s *ssm.Client, k *kms.Client) (int, error) {
		return (&FutureClient{HTTP: h, Timeout: d, BaseURL: u}).GetRecordedFutureEnrichment(c, "example.org", s, k, svcTestLogger())
	}, "recorded_future_api", `{"data":{"results":[{"risk":{"score":61}}]}}`, 61, func(t *testing.T, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Host != "offline.invalid" || r.URL.Path != "/custom" || r.Header.Get("X-RFToken") != "secret-recorded_future_api" {
			t.Fatalf("request = %s %s headers=%v", r.Method, r.URL, r.Header)
		}
	})
}

func TestRecordedFutureEmptyResults(t *testing.T) {
	s, k := svcTestSecrets(t, "")
	h := &http.Client{Transport: svcTestRoundTripper(func(*http.Request) (*http.Response, error) {
		return svcTestJSONResponse(200, `{"data":{"results":[]}}`), nil
	})}
	if _, err := (&FutureClient{HTTP: h, Timeout: time.Second}).GetRecordedFutureEnrichment(svcTestContext(context.Background()), "example.org", s, k, svcTestLogger()); err == nil {
		t.Fatal("empty results returned no error")
	}
}

func TestFutureBadURL(t *testing.T) {
	_, err := (&FutureClient{BaseURL: "%", Timeout: time.Second}).GetRecordedFutureEnrichment(svcTestContext(context.Background()), "example.org", nil, nil, svcTestLogger())
	if err == nil {
		t.Fatal("bad base URL accepted")
	}
}

func TestFutureConstructorDefaults(t *testing.T) {
	v := NewFutureClient()
	if v.HTTP == nil || v.Timeout != 15*time.Second || v.HTTP.Timeout != v.Timeout || v.BaseURL != "" {
		t.Fatalf("constructor = %+v", v)
	}
}
