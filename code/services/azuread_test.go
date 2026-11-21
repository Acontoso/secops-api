package services

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/gin-gonic/gin"
)

type azureTestCredential func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error)

func (f azureTestCredential) GetToken(ctx context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return f(ctx, o)
}

func azureTestFactory(credential azcore.TokenCredential) azureAssertionFactory {
	return func(*gin.Context, string, string, *cognitoidentity.Client, *slog.Logger) (*AzureADClient, error) {
		return &AzureADClient{credential: credential}, nil
	}
}

func azureTestToken() azcore.TokenCredential {
	return azureTestCredential(func(ctx context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
		if err := ctx.Err(); err != nil {
			return azcore.AccessToken{}, err
		}
		return azcore.AccessToken{Token: "access-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
	})
}

type azureTestBody struct {
	io.Reader
	closed bool
}

func (b *azureTestBody) Close() error { b.closed = true; return nil }

type azureTestReadError struct{}

func (azureTestReadError) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestAzureADTokenContracts(t *testing.T) {
	for _, tt := range []struct {
		name, scope string
		tokenErr    error
		cancel      bool
		wantErr     bool
		wantCalls   int
	}{
		{name: "token", scope: "scope", wantCalls: 1},
		{name: "empty scope", wantErr: true},
		{name: "credential error", scope: "scope", tokenErr: io.ErrUnexpectedEOF, wantErr: true, wantCalls: 1},
		{name: "canceled", scope: "scope", cancel: true, wantErr: true, wantCalls: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancel {
				cancel()
			}
			calls := 0
			client := &AzureADClient{credential: azureTestCredential(func(got context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
				calls++
				if !reflect.DeepEqual(opts.Scopes, []string{tt.scope}) {
					t.Errorf("scopes = %v", opts.Scopes)
				}
				if got.Err() != nil {
					return azcore.AccessToken{}, got.Err()
				}
				return azcore.AccessToken{Token: "token"}, tt.tokenErr
			})}
			got, err := client.GetAccessTokenSecret(ctx, tt.scope)
			if (err != nil) != tt.wantErr || calls != tt.wantCalls {
				t.Fatalf("token=%q err=%v calls=%d", got, err, calls)
			}
			if !tt.wantErr && got != "token" {
				t.Errorf("token = %q", got)
			}
			if tt.tokenErr != nil && !errors.Is(err, tt.tokenErr) {
				t.Errorf("wrapped error = %v", err)
			}
		})
	}
}

func TestAzureADConstructors(t *testing.T) {
	old := WH_TENANTID
	t.Cleanup(func() { WH_TENANTID = old })
	const tenant = "11111111-1111-1111-1111-111111111111"
	const clientID = "22222222-2222-2222-2222-222222222222"
	WH_TENANTID = tenant
	client, err := NewAzureADClient(clientID, "secret", awsTestLogger())
	if err != nil || client.credential == nil || client.clientID != clientID || client.tenantID != tenant {
		t.Fatalf("client = %#v, %v", client, err)
	}
	assertion, err := NewAzureADClientAssertion(awsTestContext(), clientID, tenant, nil, awsTestLogger())
	if err != nil || assertion.credential == nil || assertion.tenantID != tenant {
		t.Fatalf("assertion client = %#v, %v", assertion, err)
	}
	WH_TENANTID = "invalid/tenant"
	if _, err := NewAzureADClient(clientID, "secret", awsTestLogger()); err == nil {
		t.Error("invalid secret credential tenant accepted")
	}
	if _, err := NewAzureADClientAssertion(awsTestContext(), clientID, "invalid/tenant", nil, awsTestLogger()); err == nil {
		t.Error("invalid assertion credential tenant accepted")
	}
}

func TestUpdateCAListContracts(t *testing.T) {
	oldWH, oldMA := WH_TENANTID, MA_TENANTID
	WH_TENANTID, MA_TENANTID = "wh-tenant", "ma-tenant"
	t.Cleanup(func() { WH_TENANTID, MA_TENANTID = oldWH, oldMA })
	for _, tt := range []struct {
		name                                string
		getStatus, patchStatus              int
		getBody                             any
		failTransport                       string
		readError, factoryError, tokenError bool
		wantErr                             bool
		wantCalls                           []string
	}{
		{name: "append existing IP ranges", getBody: map[string]any{"@odata.type": "#microsoft.graph.ipNamedLocation", "ipRanges": []any{map[string]string{"@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": "192.0.2.0/24"}}}, wantCalls: []string{"GET", "PATCH"}},
		{name: "ignore non-IP location ranges", getBody: map[string]any{"@odata.type": "#microsoft.graph.countryNamedLocation", "ipRanges": []any{map[string]string{"cidrAddress": "ignored"}}}, wantCalls: []string{"GET", "PATCH"}},
		{name: "reject GET failure before PATCH", getStatus: 403, getBody: map[string]any{"error": map[string]string{"message": "denied"}}, wantErr: true, wantCalls: []string{"GET"}},
		{name: "malformed GET body", getBody: "not an object", wantErr: true, wantCalls: []string{"GET"}},
		{name: "GET read error", readError: true, wantErr: true, wantCalls: []string{"GET"}},
		{name: "GET transport error", failTransport: "GET", wantErr: true, wantCalls: []string{"GET"}},
		{name: "PATCH transport error", failTransport: "PATCH", wantErr: true, wantCalls: []string{"GET", "PATCH"}},
		{name: "PATCH HTTP error", patchStatus: 400, wantErr: true, wantCalls: []string{"GET", "PATCH"}},
		{name: "factory error", factoryError: true, wantErr: true},
		{name: "token error", tokenError: true, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			var bodies []*azureTestBody
			h := &http.Client{Transport: awsTestRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls = append(calls, r.Method)
				if r.URL.String() != "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations/request-list" || r.Header.Get("Authorization") != "Bearer access-token" || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("request = %s %s %v", r.Method, r.URL, r.Header)
				}
				if tt.failTransport == r.Method {
					return nil, io.ErrUnexpectedEOF
				}
				status, body := tt.getStatus, tt.getBody
				if r.Method == "PATCH" {
					var payload struct {
						Type     string `json:"@odata.type"`
						IPRanges []struct {
							Type string `json:"@odata.type"`
							CIDR string `json:"cidrAddress"`
						} `json:"ipRanges"`
					}
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Fatal(err)
					}
					if payload.Type != "#microsoft.graph.ipNamedLocation" || len(payload.IPRanges) == 0 {
						t.Fatalf("payload = %#v", payload)
					}
					last := payload.IPRanges[len(payload.IPRanges)-1]
					if last.CIDR != "198.51.100.1/32" || last.Type != "#microsoft.graph.iPv4CidrRange" {
						t.Errorf("new range = %#v", last)
					}
					wantRanges := 1
					if tt.name == "append existing IP ranges" {
						wantRanges = 2
					}
					if len(payload.IPRanges) != wantRanges {
						t.Errorf("range count = %d", len(payload.IPRanges))
					}
					status, body = tt.patchStatus, map[string]any{}
				}
				if status == 0 {
					status = 200
				}
				if body == nil {
					body = map[string]any{}
				}
				resp, err := awsTestResponse(status, body)
				if err != nil {
					return nil, err
				}
				tracked := &azureTestBody{Reader: resp.Body}
				if tt.readError && r.Method == "GET" {
					tracked.Reader = azureTestReadError{}
				}
				resp.Body = tracked
				bodies = append(bodies, tracked)
				return resp, nil
			})}
			factory := azureTestFactory(azureTestToken())
			if tt.factoryError {
				factory = func(*gin.Context, string, string, *cognitoidentity.Client, *slog.Logger) (*AzureADClient, error) {
					return nil, io.ErrUnexpectedEOF
				}
			}
			if tt.tokenError {
				factory = azureTestFactory(azureTestCredential(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
					return azcore.AccessToken{}, io.ErrUnexpectedEOF
				}))
			}
			got, err := updateCAList(awsTestContext(), "198.51.100.1", WH_TENANTID, "request-list", nil, awsTestLogger(), factory, h, h)
			if (err != nil) != tt.wantErr || got == tt.wantErr {
				t.Errorf("updated=%v error=%v wantErr=%v", got, err, tt.wantErr)
			}
			if !reflect.DeepEqual(calls, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", calls, tt.wantCalls)
			}
			for _, body := range bodies {
				if !body.closed {
					t.Error("response body not closed")
				}
			}
		})
	}
}

func TestUpdateCAListPublicAbortsWithoutCredential(t *testing.T) {
	if _, err := UpdateCAList(awsTestContext(), "192.0.2.1", "invalid/tenant", "list", nil, nil, nil, awsTestLogger()); err == nil {
		t.Fatal("unknown tenant produced a credential without error")
	}
}

func TestAzureRequestCancellation(t *testing.T) {
	c := awsTestContext()
	ctx, cancel := context.WithCancel(c.Request.Context())
	cancel()
	c.Request = c.Request.WithContext(ctx)
	h := &http.Client{Transport: awsTestRoundTripper(func(*http.Request) (*http.Response, error) { return nil, errors.New("canceled request reached HTTP") })}
	_, err := updateCAList(c, "192.0.2.1", "tenant", "list", nil, awsTestLogger(), azureTestFactory(azureTestToken()), h, h)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want request cancellation", err)
	}
}
