package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cloudflare/cloudflare-go"
)

func svcTestCloudflareMaps(t *testing.T) {
	t.Helper()
	oldA, oldL := AccountIDMap, ListMap
	AccountIDMap = map[string]string{"test-account": "account-id"}
	ListMap = map[string]string{"test-account": "list-id"}
	t.Cleanup(func() { AccountIDMap, ListMap = oldA, oldL })
}
func TestCloudflareConfigurationAndSecrets(t *testing.T) {
	for _, kind := range []string{"missing_account", "missing_list", "empty_account", "empty_list", "secret", "constructor"} {
		t.Run(kind, func(t *testing.T) {
			svcTestCloudflareMaps(t)
			switch kind {
			case "missing_account":
				delete(AccountIDMap, "test-account")
			case "missing_list":
				delete(ListMap, "test-account")
			case "empty_account":
				AccountIDMap["test-account"] = ""
			case "empty_list":
				ListMap["test-account"] = ""
			}
			s, k := svcTestSecrets(t, "test-account")
			if kind == "constructor" {
				s, k = svcTestSecrets(t, "")
			}
			factoryCalls := 0
			ok, err := cloudflareAddIP(svcTestContext(context.Background()), "1.2.3.4", "test-account", "INC-1", s, k, svcTestLogger(), func(token string) (*cloudflare.API, error) {
				factoryCalls++
				if kind != "constructor" {
					t.Error("SDK client created after missing config/secret")
				}
				return nil, errors.New("constructor failure")
			})
			if ok || err == nil {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
			if kind != "constructor" && factoryCalls != 0 {
				t.Errorf("factory calls=%d", factoryCalls)
			}
		})
	}
}
func TestCloudflareMissingConfigurationSuppressesSecrets(t *testing.T) {
	for _, kind := range []string{"missing_account", "missing_list", "empty_account", "empty_list"} {
		t.Run(kind, func(t *testing.T) {
			svcTestCloudflareMaps(t)
			switch kind {
			case "missing_account":
				delete(AccountIDMap, "test-account")
			case "missing_list":
				delete(ListMap, "test-account")
			case "empty_account":
				AccountIDMap["test-account"] = ""
			case "empty_list":
				ListMap["test-account"] = ""
			}
			// Nil clients prove configuration validation happens before secret access.
			ok, err := CloudflareAddIP(svcTestContext(context.Background()), "1.2.3.4", "test-account", "INC-1", nil, nil, svcTestLogger())
			if ok || err == nil {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestCloudflareSDKWorkflow(t *testing.T) {
	for _, kind := range []string{"success", "pending", "create_status", "create_decode", "create_read", "transport", "poll_status", "poll_failed", "list_status", "list_decode", "cancel", "cancel_poll"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				svcTestCloudflareMaps(t)
				s, k := svcTestSecrets(t, "")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if kind == "cancel" {
					cancel()
				}
				var calls []string
				var bodies []*svcTestBody
				polls := 0
				rt := svcTestRoundTripper(func(r *http.Request) (*http.Response, error) {
					calls = append(calls, r.Method+" "+r.URL.Path)
					if r.URL.Host != "offline.invalid" || r.Header.Get("Authorization") != "Bearer secret-test-account" || r.Header.Get("Content-Type") != "application/json" {
						t.Fatalf("request=%s headers=%v", r.URL, r.Header)
					}
					if err := r.Context().Err(); err != nil {
						return nil, err
					}
					if kind == "transport" {
						return nil, errors.New("offline")
					}
					status := 200
					raw := ""
					switch r.Method + " " + r.URL.Path {
					case "POST /accounts/account-id/rules/lists/list-id/items":
						var p []struct{ IP, Comment string }
						if e := json.NewDecoder(r.Body).Decode(&p); e != nil {
							t.Fatal(e)
						}
						if len(p) != 1 || p[0].IP != "1.2.3.4" || p[0].Comment != "Added via SOAR Incident INC-1" {
							t.Fatalf("payload=%+v", p)
						}
						raw = `{"success":true,"result":{"operation_id":"operation-id"}}`
						switch kind {
						case "create_status":
							status = 403
							raw = `{"success":false,"errors":[{"code":1000,"message":"denied"}]}`
						case "create_decode":
							raw = `{`
						case "cancel_poll":
							go func() { time.Sleep(100 * time.Millisecond); cancel() }()
						}
					case "GET /accounts/account-id/rules/lists/bulk_operations/operation-id":
						polls++
						raw = `{"success":true,"result":{"id":"operation-id","status":"completed"}}`
						if kind == "pending" && polls == 1 {
							raw = `{"success":true,"result":{"status":"pending"}}`
						}
						if kind == "poll_status" {
							status = 403
							raw = `{"success":false}`
						}
						if kind == "poll_failed" {
							raw = `{"success":true,"result":{"status":"failed","error":"bulk failure"}}`
						}
					case "GET /accounts/account-id/rules/lists/list-id/items":
						raw = `{"success":true,"result":[{"id":"item-id","ip":"1.2.3.4"}],"result_info":{"cursors":{}}}`
						if kind == "list_status" {
							status = 403
							raw = `{"success":false}`
						}
						if kind == "list_decode" {
							raw = `{`
						}
					default:
						t.Fatalf("unexpected outbound request: %s %s", r.Method, r.URL)
					}
					body := &svcTestBody{Reader: strings.NewReader(raw)}
					if kind == "create_read" {
						body.err = errors.New("read failure")
					}
					bodies = append(bodies, body)
					resp := svcTestJSONResponse(status, "")
					resp.Body = body
					return resp, nil
				})
				factory := func(token string) (*cloudflare.API, error) {
					if token != "secret-test-account" {
						t.Fatalf("token=%q", token)
					}
					return cloudflare.NewWithAPIToken(token, cloudflare.HTTPClient(&http.Client{Transport: rt}), cloudflare.BaseURL("https://offline.invalid"), cloudflare.UsingRetryPolicy(0, 0, 0), cloudflare.UsingRateLimit(1000000))
				}
				ok, err := cloudflareAddIP(svcTestContext(ctx), "1.2.3.4", "test-account", "INC-1", s, k, svcTestLogger(), factory)
				success := kind == "success" || kind == "pending"
				if ok != success || (err == nil) != success {
					t.Fatalf("ok=%v err=%v calls=%v", ok, err, calls)
				}
				want := 1
				switch kind {
				case "success", "list_status", "list_decode":
					want = 3
				case "pending":
					want = 4
				case "poll_failed", "poll_status":
					want = 2
				case "cancel":
					want = 0
				}
				if len(calls) != want {
					t.Errorf("calls=%v want %d", calls, want)
				}
				for _, b := range bodies {
					if !b.closed {
						t.Error("SDK response body not closed")
					}
				}
				if (kind == "cancel" || kind == "cancel_poll") && !errors.Is(err, context.Canceled) {
					t.Errorf("cancel error=%v", err)
				}
			})
		})
	}
}
func TestCloudflareConstructor(t *testing.T) {
	if _, err := NewCloudflareClient(""); err == nil {
		t.Fatal("empty token accepted")
	}
	v, err := NewCloudflareClient("token")
	if err != nil || v.APIToken != "token" || v.BaseURL != "https://api.cloudflare.com/client/v4" {
		t.Fatalf("client=%+v err=%v", v, err)
	}
}
func TestCloudflarePublicWorkflow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		svcTestCloudflareMaps(t)
		s, k := svcTestSecrets(t, "")
		calls := 0
		svcTestDefaultTransport(t, svcTestRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.Host != "api.cloudflare.com" {
				t.Fatalf("unexpected outbound %s", r.URL)
			}
			switch r.Method + " " + r.URL.Path {
			case "POST /client/v4/accounts/account-id/rules/lists/list-id/items":
				return svcTestJSONResponse(200, `{"success":true,"result":{"operation_id":"op"}}`), nil
			case "GET /client/v4/accounts/account-id/rules/lists/bulk_operations/op":
				return svcTestJSONResponse(200, `{"success":true,"result":{"status":"completed"}}`), nil
			case "GET /client/v4/accounts/account-id/rules/lists/list-id/items":
				return svcTestJSONResponse(200, `{"success":true,"result":[]}`), nil
			default:
				t.Fatalf("unexpected outbound %s %s", r.Method, r.URL)
				return nil, errors.New("unexpected")
			}
		}))
		ok, err := CloudflareAddIP(svcTestContext(context.Background()), "1.2.3.4", "test-account", "INC-1", s, k, svcTestLogger())
		if !ok || err != nil || calls != 3 {
			t.Fatalf("ok=%v err=%v calls=%d", ok, err, calls)
		}
	})
}
