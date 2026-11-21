package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Acontoso/soar-api/code/database"
	"github.com/Acontoso/soar-api/code/models"
	"github.com/Acontoso/soar-api/code/services"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/gin-gonic/gin"
)

// handlerFixture runs real handlers and SDK serializers. Every transport is
// fail-closed: no unexpected request can reach a live service.
type handlerFixture struct {
	mu                     sync.Mutex
	cache                  map[string]map[string]any
	reads, writes, updates []map[string]any
	events                 []string
	failRead, failWrite    bool
	failSecretAt           int
	secretCalls, apiCalls  int
	apiStatus              int
}

func av(v any) map[string]any {
	switch v := v.(type) {
	case string:
		return map[string]any{"S": v}
	case int:
		return map[string]any{"N": fmt.Sprint(v)}
	case bool:
		return map[string]any{"BOOL": v}
	case []string:
		values := make([]any, 0, len(v))
		for _, item := range v {
			values = append(values, av(item))
		}
		return map[string]any{"L": values}
	case map[string]any:
		attrs := map[string]any{}
		for k, value := range v {
			attrs[k] = av(value)
		}
		return map[string]any{"M": attrs}
	default:
		panic(fmt.Sprintf("unsupported fixture attribute %T", v))
	}
}

func attributes(fields map[string]any) map[string]any {
	result := map[string]any{}
	for k, v := range fields {
		result[k] = av(v)
	}
	return result
}

func attrString(attrs map[string]any, field string) string {
	value, _ := attrs[field].(map[string]any)
	s, _ := value["S"].(string)
	return s
}

func recordKey(attrs map[string]any) string {
	source := attrString(attrs, "EnrichmentSource")
	if source == "" {
		source = attrString(attrs, "Integration")
	}
	return attrString(attrs, "IOC") + "|" + source
}

func (f *handlerFixture) app(t *testing.T) *App {
	t.Helper()
	t.Setenv("SSM_PARAMETER_PREFIX", "/handler-tests")
	oldIOC, oldSOAR := database.IOC_TABLE_NAME, database.SOAR_ACTIONS_TABLE_NAME
	database.IOC_TABLE_NAME, database.SOAR_ACTIONS_TABLE_NAME = "handler-ioc", "handler-soar"
	t.Cleanup(func() { database.IOC_TABLE_NAME, database.SOAR_ACTIONS_TABLE_NAME = oldIOC, oldSOAR })
	if f.cache == nil {
		f.cache = map[string]map[string]any{}
	}
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		target := r.Header.Get("X-Amz-Target")
		f.events = append(f.events, target)
		sdkError := func() (*http.Response, error) {
			return jsonHTTPResponse(400, map[string]string{"__type": "ValidationException", "message": "fixture failure"})
		}
		if target != "" {
			var input map[string]any
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				return nil, err
			}
			switch target {
			case "DynamoDB_20120810.GetItem":
				key := input["Key"].(map[string]any)
				f.reads = append(f.reads, key)
				if f.failRead {
					return sdkError()
				}
				item := f.cache[recordKey(key)]
				if item == nil {
					return jsonHTTPResponse(200, map[string]any{})
				}
				return jsonHTTPResponse(200, map[string]any{"Item": item})
			case "DynamoDB_20120810.BatchGetItem":
				if f.failRead {
					return sdkError()
				}
				responses := map[string]any{}
				for table, raw := range input["RequestItems"].(map[string]any) {
					var items []map[string]any
					for _, rawKey := range raw.(map[string]any)["Keys"].([]any) {
						key := rawKey.(map[string]any)
						f.reads = append(f.reads, key)
						if item := f.cache[recordKey(key)]; item != nil {
							items = append(items, item)
						}
					}
					responses[table] = items
				}
				return jsonHTTPResponse(200, map[string]any{"Responses": responses})
			case "DynamoDB_20120810.PutItem":
				item := input["Item"].(map[string]any)
				f.writes = append(f.writes, item)
				if f.failWrite {
					return sdkError()
				}
				f.cache[recordKey(item)] = item
				return jsonHTTPResponse(200, map[string]any{})
			case "DynamoDB_20120810.UpdateItem":
				f.updates = append(f.updates, input)
				if f.failWrite {
					return sdkError()
				}
				return jsonHTTPResponse(200, map[string]any{})
			case "AmazonSSM.GetParameter":
				f.secretCalls++
				name, _ := input["Name"].(string)
				if !strings.HasPrefix(name, "/handler-tests/") {
					t.Errorf("unexpected secret namespace: %s", name)
				}
				if f.secretCalls == f.failSecretAt {
					return sdkError()
				}
				return jsonHTTPResponse(200, map[string]any{"Parameter": map[string]string{"Value": "Y2lwaGVydGV4dA=="}})
			case "TrentService.Decrypt":
				return jsonHTTPResponse(200, map[string]string{"Plaintext": "dG9rZW4="})
			default:
				t.Errorf("unexpected SDK call %s %s", target, r.URL)
				return nil, errors.New("unexpected SDK request")
			}
		}
		if r.URL.Host != "offline.invalid" {
			t.Errorf("unexpected outbound request %s", r.URL)
			return nil, errors.New("unexpected outbound request")
		}
		f.apiCalls++
		status := f.apiStatus
		if status == 0 {
			status = 200
		}
		switch r.URL.Path {
		case "/abuse":
			return jsonHTTPResponse(status, map[string]any{"data": map[string]any{"abuseConfidenceScore": 85, "countryName": "Australia", "countryCode": "AU", "totalReports": 7, "isTor": true}})
		case "/anomali":
			return jsonHTTPResponse(status, map[string]any{"average_confidence": 85})
		default:
			t.Errorf("unexpected API path: %s", r.URL)
			return nil, errors.New("unexpected API request")
		}
	})
	client := &http.Client{Transport: rt}
	cfg := aws.Config{Region: "us-east-1", HTTPClient: client, Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	return &App{
		Dynamo: dynamodb.NewFromConfig(cfg), SSM: ssm.NewFromConfig(cfg), KMS: kms.NewFromConfig(cfg), Cognito: cognitoidentity.NewFromConfig(cfg),
		AbuseIPDB: &services.AbuseIPDBClient{HTTP: client, BaseURL: "https://offline.invalid/abuse", Timeout: time.Second},
		Anomali:   &services.AnomaliClient{HTTP: client, BaseURL: "https://offline.invalid/anomali", Timeout: time.Second},
		Zscaler:   &services.ZscalerClient{HTTP: client, BaseURL: "https://offline.invalid/zscaler", Timeout: time.Second},
	}
}

func serveHandler(t *testing.T, handler gin.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("logger", slog.New(slog.NewJSONHandler(io.Discard, nil)))
	handler(c)
	return w
}

func decodeBody[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var result T
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v: %s", err, w.Body.String())
	}
	return result
}

func TestAnomaliHandlerContracts(t *testing.T) {
	for _, kind := range []string{"cached", "private", "read error", "success", "best effort write", "upstream error", "secret error"} {
		t.Run(kind, func(t *testing.T) {
			f := &handlerFixture{}
			app := f.app(t)
			ioc := "example.test"
			wantStatus := 200
			switch kind {
			case "cached":
				f.cache[ioc+"|Anomali"] = attributes(map[string]any{"IOC": ioc, "EnrichmentSource": "Anomali", "IOCType": "Domain", "MaliciousConfidence": "High", "Info": map[string]any{"Score": 85}})
			case "private":
				ioc = "10.0.0.1"
			case "read error":
				f.failRead = true
				wantStatus = 500
			case "best effort write":
				f.failWrite = true
			case "upstream error":
				f.apiStatus = 503
				wantStatus = 502
			case "secret error":
				f.failSecretAt = 1
				wantStatus = 502
			}
			w := serveHandler(t, app.AnomaliLookup, fmt.Sprintf(`{"ioc":%q,"incident_id":"INC-1"}`, ioc))
			if w.Code != wantStatus {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if wantStatus != 200 {
				if len(f.writes) != 0 || w.Body.String() != `{"error":"Internal server error"}` {
					t.Fatalf("error wrote records or changed body: %s", w.Body.String())
				}
				return
			}
			got := decodeBody[models.AnomaliResponsePayload](t, w)
			score := 85
			if kind == "private" {
				score = 0
			}
			if got.IOC != ioc || got.Score != score {
				t.Fatalf("response=%+v", got)
			}
			if kind == "cached" || kind == "private" {
				if f.apiCalls != 0 || len(f.writes) != 0 || f.secretCalls != 0 {
					t.Fatal("cache/private path reached external services")
				}
			} else {
				if len(f.writes) != 1 || f.apiCalls != 1 {
					t.Fatalf("writes=%d API=%d", len(f.writes), f.apiCalls)
				}
				if attrString(f.writes[0], "EnrichmentSource") != "Anomali" || attrString(f.writes[0], "IncidentID") != "INC-1" || attrString(f.writes[0], "IOCType") != "Domain" {
					t.Fatalf("record=%v", f.writes[0])
				}
			}
		})
	}
}

func TestCAAndDATPCacheAndDatabaseFailures(t *testing.T) {
	for _, endpoint := range []string{"AzureAD", "DATP"} {
		for _, kind := range []string{"cached", "read error"} {
			t.Run(endpoint+"/"+kind, func(t *testing.T) {
				f := &handlerFixture{failRead: kind == "read error"}
				app := f.app(t)
				f.cache["192.0.2.1|"+endpoint] = attributes(map[string]any{"IOC": "192.0.2.1", "Integration": endpoint})
				body := `{"ioc":"192.0.2.1","incident_id":"INC-1","tenant_id":"tenant","action":"Audit"}`
				handler := app.DATPBlock
				if endpoint == "AzureAD" {
					handler = app.CABlock
					body = `{"ioc":"192.0.2.1","incident_id":"INC-1","tenant_id":"tenant","list_id":"list","list_name":"name"}`
				}
				w := serveHandler(t, handler, body)
				if kind == "read error" {
					if w.Code != 500 || w.Body.String() != `{"error":"Internal server error"}` {
						t.Fatalf("read failure: %d %s", w.Code, w.Body.String())
					}
				} else {
					if w.Code != 200 {
						t.Fatalf("cached: %d %s", w.Code, w.Body.String())
					}
					if endpoint == "AzureAD" {
						got := decodeBody[models.AzureADCAResponsePayload](t, w)
						if got.IOC != "192.0.2.1" || got.Action != "Block" || got.ListName != "SOAR-API-Locations" {
							t.Fatalf("CA response=%+v", got)
						}
					} else {
						got := decodeBody[models.DATPUploadResponsePayload](t, w)
						if !got.Added || got.Platform != "DATP" || got.Action != "Audit" {
							t.Fatalf("DATP response=%+v", got)
						}
					}
				}
				if len(f.events) != 1 || len(f.writes) != 0 {
					t.Fatalf("unexpected downstream calls: %v", f.events)
				}
			})
		}
	}
}

func TestCAPrivateAndNonIP(t *testing.T) {
	for _, ioc := range []string{"10.1.2.3", "fd00::1", "example.test"} {
		t.Run(ioc, func(t *testing.T) {
			f := &handlerFixture{}
			app := f.app(t)
			w := serveHandler(t, app.CABlock, fmt.Sprintf(`{"ioc":%q,"incident_id":"INC-1","tenant_id":"tenant","list_id":"list","list_name":"name"}`, ioc))
			if ioc == "example.test" {
				if w.Code != 400 || w.Body.String() != `{"error":"Not valid IP Address"}` {
					t.Fatalf("non-IP: %d %s", w.Code, w.Body.String())
				}
			} else {
				got := decodeBody[models.AzureADCAResponsePayload](t, w)
				if w.Code != 200 || got.Action != "None" || got.IOC != ioc {
					t.Fatalf("private response: %d %+v", w.Code, got)
				}
			}
			if len(f.events) != 1 || len(f.writes) != 0 {
				t.Fatalf("private/invalid path escaped: %v", f.events)
			}
		})
	}
}

func TestSSENilClientAndSecretFailures(t *testing.T) {
	for _, kind := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			f := &handlerFixture{failSecretAt: kind}
			app := f.app(t)
			if kind == 0 {
				app.Zscaler = nil
			}
			w := serveHandler(t, app.SSEBlock, `{"iocs":["example.test"],"incident_id":"INC-1"}`)
			if w.Code != 500 || w.Body.String() != `{"error":"Internal server error"}` {
				t.Fatalf("SSE failure: %d %s", w.Code, w.Body.String())
			}
			if f.secretCalls != kind || f.apiCalls != 0 || len(f.reads) != 0 || len(f.writes) != 0 {
				t.Fatalf("downstream calls after secret failure: %v", f.events)
			}
		})
	}
}
