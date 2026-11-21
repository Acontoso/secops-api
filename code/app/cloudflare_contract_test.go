package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/Acontoso/soar-api/code/models"
	"github.com/Acontoso/soar-api/code/services"
)

func testCloudflareConfig(t *testing.T, accounts, lists map[string]string) {
	t.Helper()
	oldA, oldL := services.AccountIDMap, services.ListMap
	services.AccountIDMap, services.ListMap = accounts, lists
	t.Cleanup(func() { services.AccountIDMap, services.ListMap = oldA, oldL })
}

func TestCloudflareMissingConfigurationDoesNotPersistMembership(t *testing.T) {
	testCloudflareConfig(t, map[string]string{}, map[string]string{})
	f := &handlerFixture{}
	app := f.app(t)
	w := serveHandler(t, app.CloudflareBlock, `{"ips":["192.0.2.1","192.0.2.2"],"incident_id":"INC-1","action":"Block","account_names":["missing"]}`)
	if w.Code != http.StatusMultiStatus {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got := decodeBody[models.CloudflareBlockIPBatchResponsePayload](t, w)
	if len(got.Results) != 2 || got.Summary.Total != 2 || got.Summary.Succeeded != 0 || got.Summary.Failed != 1 {
		t.Fatalf("summary/results=%+v", got)
	}
	for _, result := range got.Results {
		if result.Added {
			t.Errorf("failed account marked added: %+v", result)
		}
	}
	if len(f.writes) != 0 || len(f.updates) != 0 || f.secretCalls != 0 {
		t.Fatalf("failed account persisted: writes=%d updates=%d secrets=%d", len(f.writes), len(f.updates), f.secretCalls)
	}
}

func TestCloudflareCacheAndReadFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{true: "read failure", false: "cached accounts"}[fail], func(t *testing.T) {
			testCloudflareConfig(t, map[string]string{}, map[string]string{})
			f := &handlerFixture{failRead: fail}
			app := f.app(t)
			f.cache["192.0.2.1|Cloudflare"] = attributes(map[string]any{"IOC": "192.0.2.1", "Integration": "Cloudflare", "Info": map[string]any{"Accounts": []string{"cached", "other"}}})
			w := serveHandler(t, app.CloudflareBlock, `{"ips":["192.0.2.1"],"incident_id":"INC-1","action":"Block","account_names":["cached","other"]}`)
			if fail {
				if w.Code != 500 || w.Body.String() != `{"error":"Internal server error"}` {
					t.Fatalf("read failure: %d %s", w.Code, w.Body.String())
				}
			} else {
				got := decodeBody[models.CloudflareBlockIPBatchResponsePayload](t, w)
				// Preserve the existing summary units: total IOCs, success per account.
				if w.Code != 200 || len(got.Results) != 2 || got.Summary.Total != 1 || got.Summary.Succeeded != 2 {
					t.Fatalf("cached results: %d %+v", w.Code, got)
				}
				for _, result := range got.Results {
					if !result.Added {
						t.Fatalf("cached result=%+v", result)
					}
				}
			}
			if len(f.writes) != 0 || len(f.updates) != 0 || f.secretCalls != 0 {
				t.Fatal("cached/read error path performed writes or secret lookup")
			}
		})
	}
}

func TestCloudflarePersistsOnlySuccessfulAccountPerIOC(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testCloudflareConfig(t, map[string]string{"allowed": "account"}, map[string]string{"allowed": "list"})
		f := &handlerFixture{}
		app := f.app(t)
		// Intercept only Cloudflare's default HTTP client; AWS has its own fixture
		// client. The failed account has no configuration and must not be persisted.
		old := http.DefaultClient
		var mu sync.Mutex
		var creates []string
		http.DefaultClient = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host != "api.cloudflare.com" {
				t.Errorf("unexpected outbound URL: %s", r.URL)
				return nil, errors.New("unexpected outbound")
			}
			path := strings.TrimPrefix(r.URL.Path, "/client/v4")
			switch r.Method + " " + path {
			case "POST /accounts/account/rules/lists/list/items":
				var payload []struct{ IP string }
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
					return nil, err
				}
				if len(payload) != 1 {
					t.Errorf("unexpected payload=%v", payload)
					return nil, errors.New("unexpected payload")
				}
				mu.Lock()
				creates = append(creates, payload[0].IP)
				mu.Unlock()
				if payload[0].IP == "192.0.2.2" {
					response, err := jsonHTTPResponse(403, map[string]any{"success": false, "errors": []any{map[string]any{"code": 1000, "message": "denied"}}})
					if response != nil {
						response.Request = r
					}
					return response, err
				}
				return jsonHTTPResponse(200, map[string]any{"success": true, "result": map[string]string{"operation_id": "op"}})
			case "GET /accounts/account/rules/lists/bulk_operations/op":
				return jsonHTTPResponse(200, map[string]any{"success": true, "result": map[string]string{"status": "completed"}})
			case "GET /accounts/account/rules/lists/list/items":
				return jsonHTTPResponse(200, map[string]any{"success": true, "result": []any{}})
			default:
				t.Errorf("unexpected Cloudflare request: %s %s", r.Method, r.URL)
				return nil, errors.New("unexpected request")
			}
		})}
		t.Cleanup(func() { http.DefaultClient = old })
		w := serveHandler(t, app.CloudflareBlock, `{"ips":["192.0.2.1","192.0.2.2"],"incident_id":"INC-1","action":"Block","account_names":["allowed","missing"]}`)
		if w.Code != 207 {
			t.Fatalf("status=%d %s", w.Code, w.Body.String())
		}
		if len(creates) != 2 {
			t.Errorf("Cloudflare creates=%v", creates)
		}
		if len(f.writes) != 1 {
			t.Fatalf("want one successful IOC persisted; writes=%v", f.writes)
		}
		item := f.writes[0]
		if attrString(item, "IOC") != "192.0.2.1" || attrString(item, "Integration") != "Cloudflare" || attrString(item, "IncidentID") != "INC-1" {
			t.Fatalf("persisted metadata=%v", item)
		}
		info := item["Info"].(map[string]any)["M"].(map[string]any)
		accounts := info["Accounts"].(map[string]any)["L"].([]any)
		if len(accounts) != 1 || accounts[0].(map[string]any)["S"] != "allowed" {
			t.Fatalf("persisted failed account: %v", accounts)
		}
	})
}
