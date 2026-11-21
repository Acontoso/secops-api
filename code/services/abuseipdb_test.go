package services

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/gin-gonic/gin"
)

type svcLookup func(*gin.Context, *http.Client, time.Duration, string, *ssm.Client, *kms.Client) (int, error)

func svcLookupContracts(t *testing.T, run svcLookup, secret, success string, want int, assertRequest func(*testing.T, *http.Request)) {
	t.Helper()
	for _, tt := range []struct {
		name, body                          string
		status                              int
		transport, read, cancel, secretFail bool
	}{
		{name: "success", status: 200, body: success}, {name: "default_timeout", status: 200, body: success},
		{name: "status", status: 403, body: `{}`}, {name: "decode", status: 200, body: `{`}, {name: "read", status: 200, read: true},
		{name: "transport", transport: true}, {name: "cancel", cancel: true}, {name: "secret", secretFail: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fail := ""
			if tt.secretFail {
				fail = secret
			}
			s, k := svcTestSecrets(t, fail)
			ctx := context.Background()
			if tt.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			calls := 0
			body := &svcTestBody{Reader: strings.NewReader(tt.body)}
			if tt.read {
				body.err = errors.New("read failure")
			}
			client := &http.Client{Transport: svcTestRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				assertRequest(t, r)
				if tt.secretFail {
					t.Error("outbound request after secret failure")
				}
				if err := r.Context().Err(); err != nil {
					return nil, err
				}
				if tt.transport {
					return nil, errors.New("transport failure")
				}
				resp := svcTestJSONResponse(tt.status, "")
				resp.Body = body
				return resp, nil
			})}
			timeout := time.Second
			if tt.name == "default_timeout" {
				timeout = 0
			}
			got, err := run(svcTestContext(ctx), client, timeout, "https://offline.invalid/custom", s, k)
			successCase := tt.name == "success" || tt.name == "default_timeout"
			if successCase {
				if err != nil || got != want {
					t.Fatalf("got %d, %v; want %d, nil", got, err, want)
				}
			} else if err == nil {
				t.Fatalf("expected error, got score %d", got)
			}
			if tt.secretFail && calls != 0 {
				t.Errorf("API calls=%d after secret failure, want 0", calls)
			}
			if calls > 0 && !tt.transport && !tt.secretFail && !tt.cancel && !body.closed {
				t.Error("response body not closed")
			}
		})
	}
}
func TestAbuseIPDBContracts(t *testing.T) {
	svcLookupContracts(t, func(c *gin.Context, h *http.Client, d time.Duration, u string, s *ssm.Client, k *kms.Client) (int, error) {
		v, e := (&AbuseIPDBClient{HTTP: h, Timeout: d, BaseURL: u}).CheckIP(c, "1.2.3.4 &x", s, k, svcTestLogger())
		if v == nil {
			return 0, e
		}
		if v.Data.CountryName != "Test" || !v.Data.IsTor || v.Data.TotalReports != 8 {
			t.Errorf("decoded=%+v", v.Data)
		}
		return v.Data.AbuseConfidenceScore, e
	}, "ipabuse_db", `{"data":{"abuseConfidenceScore":82,"countryName":"Test","totalReports":8,"isTor":true}}`, 82, func(t *testing.T, r *http.Request) {
		if r.Method != "GET" || r.URL.Host != "offline.invalid" || r.URL.Path != "/custom" || r.URL.Query().Get("ipAddress") != "1.2.3.4 &x" || r.Header.Get("Key") != "secret-ipabuse_db" || r.Header.Get("Accept") != "application/json" {
			t.Fatalf("request=%s %s headers=%v", r.Method, r.URL, r.Header)
		}
	})
}
func TestAbuseIPDBConstructorAndBadURL(t *testing.T) {
	v := NewAbuseIPDBClient()
	if v.HTTP == nil || v.Timeout != 5*time.Second || v.HTTP.Timeout != v.Timeout || v.BaseURL != "https://api.abuseipdb.com/api/v2/check" {
		t.Fatalf("constructor=%+v", v)
	}
	_, e := (&AbuseIPDBClient{BaseURL: "%", Timeout: time.Second}).CheckIP(svcTestContext(context.Background()), "ip", nil, nil, svcTestLogger())
	if e == nil {
		t.Fatal("bad URL accepted")
	}
}

func TestLookupDefaultsAndRequestCancellation(t *testing.T) {
	for _, kind := range []string{"abuse", "anomali", "future"} {
		for _, scenario := range []string{"zero_value", "negative_timeout", "cancel_in_flight", "deadline"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					s, k := svcTestSecrets(t, "")
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					calls := 0
					rt := svcTestRoundTripper(func(r *http.Request) (*http.Response, error) {
						calls++
						var wantURL string
						switch kind {
						case "abuse":
							wantURL = "https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4"
						case "anomali":
							wantURL = "https://api.threatstream.com/api/v1/inteldetails/confidence_trend/?type=confidence&value=1.2.3.4"
						case "future":
							wantURL = "https://api.recordedfuture.com/soar/v3/enrichment"
						}
						if r.URL.String() != wantURL {
							t.Fatalf("URL=%s want %s", r.URL, wantURL)
						}
						if scenario == "cancel_in_flight" {
							cancel()
							<-r.Context().Done()
							return nil, r.Context().Err()
						}
						if scenario == "deadline" {
							<-r.Context().Done()
							return nil, r.Context().Err()
						}
						if r.Context().Err() != nil {
							return nil, r.Context().Err()
						}
						return svcTestJSONResponse(200, `{"data":{"results":[{"risk":{"score":0}}]}}`), nil
					})
					svcTestDefaultTransport(t, rt)
					timeout := time.Duration(0)
					if scenario == "negative_timeout" {
						timeout = -time.Second
					}
					if scenario == "cancel_in_flight" {
						timeout = time.Second
					}
					if scenario == "deadline" {
						timeout = 100 * time.Millisecond
					}
					var err error
					switch kind {
					case "abuse":
						_, err = (&AbuseIPDBClient{Timeout: timeout}).CheckIP(svcTestContext(ctx), "1.2.3.4", s, k, svcTestLogger())
					case "anomali":
						_, err = (&AnomaliClient{Timeout: timeout}).CheckIOC(svcTestContext(ctx), "1.2.3.4", s, k, svcTestLogger())
					case "future":
						_, err = (&FutureClient{Timeout: timeout}).GetRecordedFutureEnrichment(svcTestContext(ctx), "1.2.3.4", s, k, svcTestLogger())
					}
					switch scenario {
					case "zero_value", "negative_timeout":
						if err != nil {
							t.Fatalf("defaults: %v", err)
						}
					case "cancel_in_flight":
						if !errors.Is(err, context.Canceled) {
							t.Fatalf("cancellation: %v", err)
						}
					case "deadline":
						if !errors.Is(err, context.DeadlineExceeded) {
							t.Fatalf("deadline: %v", err)
						}
					}
					if calls != 1 {
						t.Errorf("calls=%d want 1", calls)
					}
				})
			})
		}
	}
}
