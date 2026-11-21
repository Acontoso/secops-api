package services

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestZscalerRequests(t *testing.T) {
	for _, tc := range []struct{ ioc, id, kind, name string }{
		{"example.org", ZSCALER_SOAR_FQDN_LIST, "DSTN_FQDN", "SOAR Malicious Domain List"},
		{"1.2.3.4", ZSCALER_SOAR_IP_LIST, "DSTN_IP", "SOAR Malicious IP Address List"},
		{"2001:db8::1", ZSCALER_SOAR_IP_LIST, "DSTN_IP", "SOAR Malicious IP Address List"},
	} {
		for _, defaults := range []bool{false, true} {
			t.Run(tc.ioc+"/"+map[bool]string{false: "custom", true: "defaults"}[defaults], func(t *testing.T) {
				body := &svcTestBody{Reader: strings.NewReader("")}
				calls := 0
				rt := svcTestRoundTripper(func(r *http.Request) (*http.Response, error) {
					calls++
					host, path := "offline.invalid", "/groups/"+tc.id
					if defaults {
						host = "zsapi.zscalerdc.net"
						path = "/api/v1/ipDestinationGroups/" + tc.id
					}
					if r.Context().Err() != nil {
						t.Fatalf("premature context error: %v", r.Context().Err())
					}
					if r.Method != "PUT" || r.URL.Host != host || r.URL.Path != path || r.URL.Query().Get("override") != "false" || r.Header.Get("Authorization") != "Bearer token" || r.Header.Get("Content-Type") != "application/json" {
						t.Fatalf("request=%s %s headers=%v", r.Method, r.URL, r.Header)
					}
					var p struct {
						Addresses  []string
						Type, Name string
					}
					if e := json.NewDecoder(r.Body).Decode(&p); e != nil {
						t.Fatal(e)
					}
					if len(p.Addresses) != 1 || p.Addresses[0] != tc.ioc || p.Type != tc.kind || p.Name != tc.name {
						t.Fatalf("payload=%+v", p)
					}
					resp := svcTestJSONResponse(204, "")
					resp.Body = body
					return resp, nil
				})
				v := &ZscalerClient{HTTP: &http.Client{Transport: rt}, Timeout: time.Second, BaseURL: "https://offline.invalid/groups"}
				if defaults {
					v = &ZscalerClient{}
					svcTestDefaultTransport(t, rt)
				}
				ok, err := v.BlockIOC(svcTestContext(context.Background()), tc.ioc, "token", svcTestLogger())
				if err != nil || !ok || calls != 1 || !body.closed {
					t.Fatalf("ok=%v err=%v calls=%d closed=%v", ok, err, calls, body.closed)
				}
			})
		}
	}
}
func TestZscalerUnsupported(t *testing.T) {
	h := &http.Client{Transport: svcTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		t.Errorf("unsupported type reached transport: %s", r.URL)
		return nil, errors.New("unexpected")
	})}
	ok, err := (&ZscalerClient{HTTP: h, Timeout: time.Second}).BlockIOC(svcTestContext(context.Background()), strings.Repeat("a", 32), "token", svcTestLogger())
	if ok || err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("ok=%v error=%v", ok, err)
	}
}
func TestZscalerRetryContracts(t *testing.T) {
	for _, kind := range []string{"transport_then_success", "429_seconds", "429_date", "429_invalid", "429_past", "429_cap", "429_exhaustion", "transport_exhaustion", "status", "cancel_transport", "cancel_backoff", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := 0
				var bodies []*svcTestBody
				var payloads []string
				var callTimes []time.Time
				h := &http.Client{Transport: svcTestRoundTripper(func(r *http.Request) (*http.Response, error) {
					calls++
					callTimes = append(callTimes, time.Now())
					b, _ := io.ReadAll(r.Body)
					payloads = append(payloads, string(b))
					if kind == "cancel_transport" {
						cancel()
						return nil, context.Canceled
					}
					if (kind == "transport_then_success" && calls == 1) || kind == "transport_exhaustion" {
						return nil, errors.New("offline transport failure")
					}
					resp := svcTestJSONResponse(200, "")
					if kind == "status" {
						resp.StatusCode = 400
						resp.Status = "400 Bad Request"
					} else if kind != "transport_then_success" && (calls == 1 || kind == "429_exhaustion" || kind == "deadline") {
						resp.StatusCode = 429
						resp.Status = "429 Too Many Requests"
						switch kind {
						case "429_seconds":
							resp.Header.Set("Retry-After", "2")
						case "429_date":
							resp.Header.Set("Retry-After", time.Now().Add(3*time.Second).UTC().Format(http.TimeFormat))
						case "429_past":
							resp.Header.Set("Retry-After", time.Now().Add(-time.Second).UTC().Format(http.TimeFormat))
						case "429_invalid":
							resp.Header.Set("Retry-After", "not-a-delay")
						case "429_cap":
							resp.Header.Set("Retry-After", "1000")
						}
					}
					body := &svcTestBody{Reader: strings.NewReader("")}
					bodies = append(bodies, body)
					resp.Body = body
					if kind == "cancel_backoff" {
						go func() { time.Sleep(100 * time.Millisecond); cancel() }()
					}
					return resp, nil
				})}
				timeout := 5 * time.Minute
				if kind == "deadline" {
					timeout = time.Second
				}
				ok, err := (&ZscalerClient{HTTP: h, Timeout: timeout}).BlockIOC(svcTestContext(ctx), "example.org", "token", svcTestLogger())
				fail := strings.Contains(kind, "exhaustion") || kind == "status" || strings.HasPrefix(kind, "cancel") || kind == "deadline"
				if fail {
					if err == nil || ok {
						t.Fatalf("ok=%v err=%v", ok, err)
					}
				} else if err != nil || !ok {
					t.Fatalf("ok=%v err=%v", ok, err)
				}
				wantCalls := 2
				if strings.Contains(kind, "exhaustion") {
					wantCalls = 6
				}
				if kind == "status" || strings.HasPrefix(kind, "cancel") {
					wantCalls = 1
				}
				if kind != "deadline" && calls != wantCalls {
					t.Errorf("calls=%d want %d", calls, wantCalls)
				}
				if strings.Contains(kind, "exhaustion") && !strings.Contains(err.Error(), "after retries") {
					t.Errorf("exhaustion error=%v", err)
				}
				if strings.HasPrefix(kind, "cancel") && !errors.Is(err, context.Canceled) {
					t.Errorf("cancel error=%v", err)
				}
				if kind == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("deadline error=%v", err)
				}
				for _, b := range bodies {
					if !b.closed {
						t.Error("retry body not closed")
					}
				}
				for _, p := range payloads {
					if p != payloads[0] {
						t.Error("retry payload changed")
					}
				}
				if len(callTimes) > 1 {
					delay := callTimes[1].Sub(callTimes[0])
					min, max := 500*time.Millisecond, 750*time.Millisecond
					switch kind {
					case "429_seconds":
						min, max = 2*time.Second, 2250*time.Millisecond
					case "429_date":
						min, max = 3*time.Second, 3250*time.Millisecond
					case "429_cap":
						min, max = 30*time.Second, 30*time.Second
					}
					if delay < min || delay > max {
						t.Errorf("retry delay=%v want [%v,%v]", delay, min, max)
					}
				}
			})
		})
	}
}
func TestZscalerActivation(t *testing.T) {
	for _, kind := range []string{"success", "status", "transport", "cancel", "public"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancel" {
				cancel()
			}
			body := &svcTestBody{Reader: strings.NewReader("")}
			rt := svcTestRoundTripper(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != "https://zsapi.zscalerdc.net/api/v1/status/activate" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer token" || r.Header.Get("Content-Type") != "application/json" {
					t.Fatalf("request=%s %s %v", r.Method, r.URL, r.Header)
				}
				if err := r.Context().Err(); err != nil {
					return nil, err
				}
				if kind == "transport" {
					return nil, errors.New("offline")
				}
				resp := svcTestJSONResponse(204, "")
				if kind == "status" {
					resp = svcTestJSONResponse(403, "")
				}
				resp.Body = body
				return resp, nil
			})
			var ok bool
			var err error
			if kind == "public" {
				svcTestDefaultTransport(t, rt)
				ok, err = ActivateChange(svcTestContext(ctx), "token", svcTestLogger())
			} else {
				ok, err = activateChangeWithClient(svcTestContext(ctx), "token", svcTestLogger(), &http.Client{Transport: rt})
			}
			success := kind == "success" || kind == "public"
			if success != (err == nil) || ok != success {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
			if (success || kind == "status") && !body.closed {
				t.Error("body not closed")
			}
		})
	}
}
func TestZscalerConstructor(t *testing.T) {
	v := NewZscalerClient()
	if v.HTTP == nil || v.Timeout != 30*time.Second || v.HTTP.Timeout != v.Timeout || v.BaseURL != "https://zsapi.zscalerdc.net/api/v1/ipDestinationGroups" {
		t.Fatalf("constructor=%+v", v)
	}
}
