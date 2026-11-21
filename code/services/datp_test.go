package services

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/gin-gonic/gin"
)

func TestConvertToDATPIOC(t *testing.T) {
	for _, tt := range []struct{ kind, want string }{{"IPv4", "IpAddress"}, {"Domain", "DomainName"}, {"MD5", "FileMd5"}, {"SHA1", "FileSha1"}, {"SHA256", "FileSha256"}, {"IPv6", ""}, {"unknown", ""}} {
		if got := convertToDATPIOC(tt.kind); got != tt.want {
			t.Errorf("convertToDATPIOC(%q) = %q, want %q", tt.kind, got, tt.want)
		}
	}
}

func TestDATPIndicatorContracts(t *testing.T) {
	for _, tt := range []struct {
		name                                      string
		status                                    int
		body                                      any
		readErr, transportErr, wantFound, wantErr bool
	}{
		{name: "found", body: map[string]any{"value": []any{map[string]string{"id": "existing"}}}, wantFound: true},
		{name: "not found", body: map[string]any{"value": []any{}}},
		{name: "HTTP error", status: 403, body: map[string]string{"error": "denied"}, wantErr: true},
		{name: "decode error", body: "invalid object", wantErr: true},
		{name: "read error", readErr: true, wantErr: true},
		{name: "transport error", transportErr: true, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var tracked *azureTestBody
			h := &http.Client{Transport: awsTestRoundTripper(func(r *http.Request) (*http.Response, error) {
				if r.Method != "GET" || r.URL.Host != "api.securitycenter.microsoft.com" || r.URL.Query().Get("$filter") != "indicatorValue eq 'example.test'" || r.Header.Get("Authorization") != "Bearer access-token" || r.Header.Get("Accept") != "application/json" {
					t.Errorf("request = %s %s %v", r.Method, r.URL, r.Header)
				}
				if tt.transportErr {
					return nil, io.ErrUnexpectedEOF
				}
				status := tt.status
				if status == 0 {
					status = 200
				}
				resp, err := awsTestResponse(status, tt.body)
				if err != nil {
					return nil, err
				}
				tracked = &azureTestBody{Reader: resp.Body}
				if tt.readErr {
					tracked.Reader = azureTestReadError{}
				}
				resp.Body = tracked
				return resp, nil
			})}
			got, err := checkIndicatorDATPWithClient(awsTestContext(), "example.test", "access-token", "Domain", awsTestLogger(), h)
			if got != tt.wantFound || (err != nil) != tt.wantErr {
				t.Errorf("found=%v error=%v", got, err)
			}
			if tracked != nil && !tracked.closed {
				t.Error("response body not closed")
			}
		})
	}
	if _, err := checkIndicatorDATP(awsTestContext(), "::1", "token", "IPv6", awsTestLogger()); err == nil {
		t.Error("unsupported IPv6 indicator accepted")
	}
}

func TestUploadDATPContracts(t *testing.T) {
	for _, tt := range []struct {
		name, ioc, kind                                 string
		existing, factoryErr, tokenErr, getErr, postErr bool
		wantErr                                         bool
		wantCalls                                       []string
	}{
		{name: "upload IP", ioc: "192.0.2.1", kind: "IpAddress", wantCalls: []string{"GET", "POST"}},
		{name: "upload domain", ioc: "example.test", kind: "DomainName", wantCalls: []string{"GET", "POST"}},
		{name: "upload hash", ioc: "d41d8cd98f00b204e9800998ecf8427e", kind: "FileMd5", wantCalls: []string{"GET", "POST"}},
		{name: "existing indicator", ioc: "192.0.2.1", existing: true, wantCalls: []string{"GET"}},
		{name: "credential construction", ioc: "192.0.2.1", factoryErr: true, wantErr: true},
		{name: "token failure", ioc: "192.0.2.1", tokenErr: true, wantErr: true},
		{name: "indicator failure", ioc: "192.0.2.1", getErr: true, wantErr: true, wantCalls: []string{"GET"}},
		{name: "upload failure", ioc: "192.0.2.1", kind: "IpAddress", postErr: true, wantErr: true, wantCalls: []string{"GET", "POST"}},
		{name: "IPv6 remains unsupported", ioc: "2001:db8::1", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			before := time.Now()
			h := &http.Client{Transport: awsTestRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls = append(calls, r.Method)
				if r.URL.Host != "api.securitycenter.microsoft.com" || r.URL.Path != "/api/indicators" || r.Header.Get("Authorization") != "Bearer access-token" {
					t.Errorf("request = %s %s %v", r.Method, r.URL, r.Header)
				}
				if r.Method == "GET" {
					if tt.getErr {
						return awsTestResponse(500, map[string]string{"error": "lookup failed"})
					}
					values := []any{}
					if tt.existing {
						values = append(values, map[string]string{"id": "existing"})
					}
					return awsTestResponse(200, map[string]any{"value": values})
				}
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				if payload["indicatorValue"] != tt.ioc || payload["indicatorType"] != tt.kind || payload["action"] != "Block" || payload["generateAlert"] != true || payload["severity"] != "High" {
					t.Errorf("payload = %#v", payload)
				}
				if payload["description"] != "SOAR API Automated Response - incident" || !strings.HasPrefix(payload["title"].(string), "SOARAPI-incident-") {
					t.Errorf("metadata = %#v", payload)
				}
				epoch, err := strconv.ParseInt(payload["title"].(string)[strings.LastIndex(payload["title"].(string), "-")+1:], 10, 64)
				if err != nil || epoch < before.Unix() || epoch > time.Now().Unix() {
					t.Errorf("title timestamp = %v %v", epoch, err)
				}
				expires, err := time.Parse(time.RFC3339, payload["expirationTime"].(string))
				if err != nil || expires.Before(before.UTC().Add(52*7*24*time.Hour).Truncate(time.Second)) || expires.After(time.Now().UTC().Add(52*7*24*time.Hour)) {
					t.Errorf("expiration = %v %v", expires, err)
				}
				if tt.postErr {
					return awsTestResponse(400, map[string]string{"error": "upload failed"})
				}
				return awsTestResponse(201, map[string]any{})
			})}
			factory := azureTestFactory(azureTestToken())
			if tt.factoryErr {
				factory = func(*gin.Context, string, string, *cognitoidentity.Client, *slog.Logger) (*AzureADClient, error) {
					return nil, io.ErrUnexpectedEOF
				}
			}
			if tt.tokenErr {
				factory = azureTestFactory(azureTestCredential(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
					return azcore.AccessToken{}, io.ErrUnexpectedEOF
				}))
			}
			got, err := uploadIOCToDATP(awsTestContext(), tt.ioc, "tenant", "Block", "incident", nil, awsTestLogger(), factory, h)
			if (err != nil) != tt.wantErr || got == tt.wantErr {
				t.Errorf("uploaded=%v err=%v wantErr=%v", got, err, tt.wantErr)
			}
			if !reflect.DeepEqual(calls, tt.wantCalls) {
				t.Errorf("calls=%v want=%v", calls, tt.wantCalls)
			}
		})
	}
}

func TestUploadDATPPublicAbortsWithoutCredential(t *testing.T) {
	if _, err := UploadIOCToDATP(awsTestContext(), "192.0.2.1", "invalid/tenant", "Block", "incident", nil, awsTestLogger()); err == nil {
		t.Fatal("invalid tenant produced a credential without error")
	}
}

func TestDATPRequestCancellation(t *testing.T) {
	for _, tt := range []struct {
		name string
		run  func(*gin.Context, *http.Client) error
	}{
		{"upload", func(c *gin.Context, h *http.Client) error {
			_, err := uploadIOCToDATP(c, "192.0.2.1", "tenant", "Block", "incident", nil, awsTestLogger(), azureTestFactory(azureTestToken()), h)
			return err
		}},
		{"indicator", func(c *gin.Context, h *http.Client) error {
			_, err := checkIndicatorDATPWithClient(c, "192.0.2.1", "token", "IPv4", awsTestLogger(), h)
			return err
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := awsTestContext()
			ctx, cancel := context.WithCancel(c.Request.Context())
			cancel()
			c.Request = c.Request.WithContext(ctx)
			h := &http.Client{Transport: awsTestRoundTripper(func(r *http.Request) (*http.Response, error) {
				if r.Context().Err() != nil {
					return nil, r.Context().Err()
				}
				return nil, errors.New("canceled request reached HTTP")
			})}
			if err := tt.run(c, h); !errors.Is(err, context.Canceled) {
				t.Fatalf("error=%v want cancellation", err)
			}
		})
	}
}
