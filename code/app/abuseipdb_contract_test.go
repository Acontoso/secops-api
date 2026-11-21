package app

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/Acontoso/soar-api/code/models"
)

func TestAbuseIPCanonicalCacheSource(t *testing.T) {
	f := &handlerFixture{}
	app := f.app(t)
	const body = `{"ip":"192.0.2.1","incident_id":"INC-1"}`
	first := serveHandler(t, app.IPLookup, body)
	if first.Code != http.StatusOK || f.apiCalls != 1 || len(f.writes) != 1 {
		t.Fatalf("initial lookup: %d %s", first.Code, first.Body.String())
	}
	if got := attrString(f.writes[0], "EnrichmentSource"); got != "AbuseIPDB" {
		t.Fatalf("canonical source = %q", got)
	}
	second := serveHandler(t, app.IPLookup, body)
	if second.Code != http.StatusOK || f.apiCalls != 1 || len(f.writes) != 1 {
		t.Fatalf("second lookup failed to reuse written cache: status=%d API calls=%d writes=%d", second.Code, f.apiCalls, len(f.writes))
	}
	for _, key := range f.reads {
		if attrString(key, "EnrichmentSource") != "AbuseIPDB" {
			t.Errorf("read source=%q", attrString(key, "EnrichmentSource"))
		}
	}
	if got := decodeBody[models.ClientAbuseIPResponsePayload](t, second); got.Country != "AU" || got.AbuseConfidenceScore != 85 || got.ReportCount != 7 || !got.TOR || !got.Exists {
		t.Fatalf("cached result=%+v", got)
	}
	manual := serveHandler(t, app.ManualIPLookup, `{"ip":"192.0.2.1"}`)
	if got := decodeBody[models.ClientAbuseIPResponsePayload](t, manual); manual.Code != 200 || !got.Exists || got.AbuseConfidenceScore != 85 {
		t.Fatalf("manual lookup did not reuse canonical cache: %d %+v", manual.Code, got)
	}
	if f.apiCalls != 1 || len(f.writes) != 1 {
		t.Fatal("manual cache lookup reached upstream")
	}
}

func TestAbuseIPReadAndEarlyReturnContracts(t *testing.T) {
	for _, manual := range []bool{false, true} {
		for _, kind := range []string{"private IPv4", "private IPv6", "invalid", "cached", "absent", "read error"} {
			t.Run(fmt.Sprintf("manual=%v/%s", manual, kind), func(t *testing.T) {
				f := &handlerFixture{}
				app := f.app(t)
				handler := app.IPLookup
				if manual {
					handler = app.ManualIPLookup
				}
				ip := "192.0.2.1"
				switch kind {
				case "private IPv4":
					ip = "10.0.0.1"
				case "private IPv6":
					ip = "fd00::1"
				case "invalid":
					ip = "not-ip"
				case "cached":
					f.cache[ip+"|AbuseIPDB"] = attributes(map[string]any{"IOC": ip, "EnrichmentSource": "AbuseIPDB", "MaliciousConfidence": "High", "Info": map[string]any{"CountryCode": "AU", "ReportCount": 7, "Score": 85, "TOR": true}})
				case "read error":
					f.failRead = true
				case "absent":
					app.AbuseIPDB = nil
				}
				body := fmt.Sprintf(`{"ip":%q}`, ip)
				if !manual {
					body = fmt.Sprintf(`{"ip":%q,"incident_id":"INC-1"}`, ip)
				}
				w := serveHandler(t, handler, body)
				want := 200
				if kind == "invalid" {
					want = 400
				}
				if kind == "read error" || (!manual && kind == "absent") {
					want = 500
				}
				if w.Code != want {
					t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body.String())
				}
				if want == 200 {
					got := decodeBody[models.ClientAbuseIPResponsePayload](t, w)
					if got.IOC != ip {
						t.Fatalf("IOC=%q", got.IOC)
					}
					if kind == "cached" && (!got.Exists || got.Country != "AU" || got.AbuseConfidenceScore != 85 || got.ReportCount != 7 || !got.TOR) {
						t.Fatalf("cached=%+v", got)
					}
					if kind == "private IPv4" || kind == "private IPv6" {
						if !got.Private || got.Exists != manual || got.AbuseConfidenceScore != 0 || got.Country != "None" {
							t.Fatalf("private=%+v", got)
						}
					}
					if kind == "absent" && (got.Exists || got.Private || got.Country != "None") {
						t.Fatalf("absent=%+v", got)
					}
				}
				if f.apiCalls != 0 || f.secretCalls != 0 || len(f.writes) != 0 {
					t.Fatalf("early-return path reached external services: %v", f.events)
				}
				if kind == "invalid" || kind == "private IPv4" || kind == "private IPv6" {
					if len(f.reads) != 0 {
						t.Fatal("invalid/private lookup read database")
					}
				}
			})
		}
	}
}

func TestAbuseIPFreshLookupAndBestEffortPersistence(t *testing.T) {
	for _, kind := range []string{"success", "save failure", "upstream failure", "secret failure"} {
		t.Run(kind, func(t *testing.T) {
			f := &handlerFixture{failWrite: kind == "save failure"}
			app := f.app(t)
			if kind == "upstream failure" {
				f.apiStatus = 503
			}
			if kind == "secret failure" {
				f.failSecretAt = 1
			}
			w := serveHandler(t, app.IPLookup, `{"ip":"192.0.2.1","incident_id":"INC-1"}`)
			if kind == "upstream failure" || kind == "secret failure" {
				if w.Code != 502 || len(f.writes) != 0 || w.Body.String() != `{"error":"Internal server error"}` {
					t.Fatalf("failure=%d %s writes=%d", w.Code, w.Body.String(), len(f.writes))
				}
				return
			}
			got := decodeBody[models.ClientAbuseIPResponsePayload](t, w)
			if w.Code != 200 || !got.Exists || got.Private || !got.TOR || got.Country != "Australia" || got.ReportCount != 7 || got.AbuseConfidenceScore != 85 {
				t.Fatalf("fresh result=%d %+v", w.Code, got)
			}
			if len(f.writes) != 1 {
				t.Fatalf("write count=%d", len(f.writes))
			}
			item := f.writes[0]
			if attrString(item, "IOC") != "192.0.2.1" || attrString(item, "IOCType") != "IPv4" || attrString(item, "IncidentID") != "INC-1" || attrString(item, "MaliciousConfidence") != string(models.GetMaliciousConfidenceLevel(85)) || attrString(item, "Date") == "" {
				t.Fatalf("persisted record=%v", item)
			}
		})
	}
}

func TestManualAbuseIPMandatoryPersistence(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			f := &handlerFixture{failWrite: fail}
			app := f.app(t)
			w := serveHandler(t, app.ManualPutAbuseIP, `{"ip":"192.0.2.1","public":true,"abuse_confidence_score":85,"country":"Australia","country_code":"AU","report_count":7,"incident_id":"INC-1"}`)
			wantStatus, wantBody := 200, `{"Added":true}`
			if fail {
				wantStatus, wantBody = 500, `{"Added":false}`
			}
			if w.Code != wantStatus || w.Body.String() != wantBody {
				t.Fatalf("manual add=%d %s", w.Code, w.Body.String())
			}
			if len(f.writes) != 1 || len(f.reads) != 0 || f.apiCalls != 0 || f.secretCalls != 0 {
				t.Fatalf("unexpected manual calls: %v", f.events)
			}
			if attrString(f.writes[0], "EnrichmentSource") != "AbuseIPDB" || attrString(f.writes[0], "IOCType") != "IPv4" {
				t.Fatalf("manual record=%v", f.writes[0])
			}
		})
	}
}
