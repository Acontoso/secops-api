package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Acontoso/soar-api/code/database"
	"github.com/Acontoso/soar-api/code/models"
	"github.com/Acontoso/soar-api/code/services"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/gin-gonic/gin"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// recordedFutureFixture intercepts every SDK and enrichment request in memory.
// It exercises the real handler and service code without live cloud services.
type recordedFutureFixture struct {
	cached        map[string]int
	scores        map[string]int
	lookupErrorAt int
	failSave      bool
	lookupCount   int
	events        []string
	written       []models.IOCTable
}

func jsonHTTPResponse(status int, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.0"}},
		Body:       io.NopCloser(bytes.NewReader(data)),
	}, nil
}

func (f *recordedFutureFixture) app(t *testing.T) *App {
	t.Helper()
	oldTable := database.IOC_TABLE_NAME
	database.IOC_TABLE_NAME = "recorded-future-test"
	t.Cleanup(func() { database.IOC_TABLE_NAME = oldTable })

	transport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		switch r.Header.Get("X-Amz-Target") {
		case "AmazonSSM.GetParameter":
			return jsonHTTPResponse(http.StatusOK, map[string]any{
				"Parameter": map[string]string{"Value": "Y2lwaGVydGV4dA=="},
			})
		case "TrentService.Decrypt":
			return jsonHTTPResponse(http.StatusOK, map[string]string{"Plaintext": "dG9rZW4="})
		case "DynamoDB_20120810.BatchGetItem":
			var input struct {
				RequestItems map[string]struct {
					Keys []map[string]struct{ S string }
				}
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				return nil, err
			}
			var iocs []string
			var records []any
			for _, key := range input.RequestItems[database.IOC_TABLE_NAME].Keys {
				ioc := key["IOC"].S
				iocs = append(iocs, ioc)
				if score, ok := f.cached[ioc]; ok {
					records = append(records, map[string]any{
						"IOC": map[string]string{"S": ioc},
						"Info": map[string]any{"M": map[string]any{
							"Score": map[string]string{"N": fmt.Sprint(score)},
						}},
					})
				}
			}
			f.events = append(f.events, "lookup:"+strings.Join(iocs, ","))
			f.lookupCount++
			if f.lookupCount == f.lookupErrorAt {
				return jsonHTTPResponse(http.StatusBadRequest, map[string]string{"__type": "ValidationException", "message": "lookup failed"})
			}
			if len(records) == 0 {
				return jsonHTTPResponse(http.StatusOK, map[string]any{})
			}
			return jsonHTTPResponse(http.StatusOK, map[string]any{
				"Responses": map[string]any{database.IOC_TABLE_NAME: records},
			})
		case "DynamoDB_20120810.BatchWriteItem":
			var input struct {
				RequestItems map[string][]struct {
					PutRequest struct {
						Item map[string]json.RawMessage
					}
				}
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				return nil, err
			}
			var iocs []string
			for _, write := range input.RequestItems[database.IOC_TABLE_NAME] {
				readString := func(key string) string {
					var attr struct{ S string }
					if err := json.Unmarshal(write.PutRequest.Item[key], &attr); err != nil {
						t.Errorf("decode written %s: %v", key, err)
					}
					return attr.S
				}
				record := models.IOCTable{
					IOC: readString("IOC"), IncidentID: readString("IncidentID"),
					IOCType: readString("IOCType"), EnrichmentSource: readString("EnrichmentSource"),
					MaliciousConfidence: readString("MaliciousConfidence"), Date: readString("Date"),
				}
				iocs = append(iocs, record.IOC)
				f.written = append(f.written, record)
			}
			f.events = append(f.events, "save:"+strings.Join(iocs, ","))
			if f.failSave {
				return jsonHTTPResponse(http.StatusBadRequest, map[string]string{"__type": "ValidationException", "message": "save failed"})
			}
			return jsonHTTPResponse(http.StatusOK, map[string]any{})
		}

		if r.URL.Host != "api.recordedfuture.com" {
			return nil, fmt.Errorf("unexpected request: %s %s", r.URL, r.Header.Get("X-Amz-Target"))
		}
		if r.Header.Get("X-RFToken") != "token" {
			t.Errorf("X-RFToken = %q, want decrypted token", r.Header.Get("X-RFToken"))
		}
		var payload models.RecordFutureAPICallSOAR
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			return nil, err
		}
		iocs := append(append(payload.IP, payload.Domain...), payload.Hash...)
		if len(iocs) != 1 {
			return nil, fmt.Errorf("enrichment payload = %#v, want one IOC", payload)
		}
		ioc := iocs[0]
		f.events = append(f.events, "enrich:"+ioc)
		score, ok := f.scores[ioc]
		if !ok {
			return jsonHTTPResponse(http.StatusBadGateway, map[string]string{"error": "enrichment failed"})
		}
		return jsonHTTPResponse(http.StatusOK, map[string]any{
			"data": map[string]any{"results": []any{map[string]any{"risk": map[string]int{"score": score}}}},
		})
	})

	client := &http.Client{Transport: transport}
	cfg := aws.Config{
		Region: "ap-southeast-2", HTTPClient: client,
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		Retryer:     func() aws.Retryer { return aws.NopRetryer{} },
	}
	return &App{
		Dynamo: dynamodb.NewFromConfig(cfg), SSM: ssm.NewFromConfig(cfg), KMS: kms.NewFromConfig(cfg),
		RecordedFuture: &services.FutureClient{HTTP: client, Timeout: time.Second},
	}
}

func TestRecordedFutureOrchestration(t *testing.T) {
	const hash = "d41d8cd98f00b204e9800998ecf8427e"
	for _, tt := range []struct {
		name       string
		body       string
		fixture    recordedFutureFixture
		status     int
		want       models.RecordSOARBatchResponsePayload
		wantEvents []string
	}{
		{
			name: "empty batch preserves null results", body: `{"incident_id":"test"}`,
			status: http.StatusOK,
		},
		{
			name:    "cached results count as successful enrichments",
			body:    `{"ips":["192.0.2.1"],"domains":["example.test"],"hashes":["` + hash + `"],"incident_id":"test"}`,
			fixture: recordedFutureFixture{cached: map[string]int{"192.0.2.1": 70, "example.test": 50, hash: 25}},
			status:  http.StatusOK,
			want: models.RecordSOARBatchResponsePayload{
				Results: []models.RecordSOARResponsePayload{{IOC: "192.0.2.1", Score: 70, Success: true}, {IOC: "example.test", Score: 50, Success: true}, {IOC: hash, Score: 25, Success: true}},
				Summary: models.RecordSOARResponseSummary{Total: 3, Succeeded: 3},
			},
			wantEvents: []string{"lookup:192.0.2.1", "lookup:example.test", "lookup:" + hash},
		},
		{
			name:    "mixed cached and fresh successes are both counted",
			body:    `{"ips":["192.0.2.1","192.0.2.2"],"incident_id":"test"}`,
			fixture: recordedFutureFixture{cached: map[string]int{"192.0.2.1": 70}, scores: map[string]int{"192.0.2.2": 50}},
			status:  http.StatusOK,
			want: models.RecordSOARBatchResponsePayload{
				Results: []models.RecordSOARResponsePayload{{IOC: "192.0.2.2", Score: 50, Success: true}, {IOC: "192.0.2.1", Score: 70, Success: true}},
				Summary: models.RecordSOARResponseSummary{Total: 2, Succeeded: 2},
			},
			wantEvents: []string{"lookup:192.0.2.1,192.0.2.2", "enrich:192.0.2.2", "save:192.0.2.2"},
		},
		{
			name:    "mixed failures preserve duplicates and category ordering",
			body:    `{"ips":["192.0.2.1","not-ip","192.0.2.1"],"domains":["example.test","192.0.2.2","err.test"],"hashes":["` + hash + `","not-hash"],"incident_id":"test"}`,
			fixture: recordedFutureFixture{scores: map[string]int{"192.0.2.1": 70, "example.test": 50, hash: 25}},
			status:  http.StatusMultiStatus,
			want: models.RecordSOARBatchResponsePayload{
				Results: []models.RecordSOARResponsePayload{
					{IOC: "192.0.2.1", Score: 70, Success: true}, {IOC: "not-ip"}, {IOC: "192.0.2.1", Score: 70, Success: true},
					{IOC: "example.test", Score: 50, Success: true}, {IOC: "192.0.2.2"}, {IOC: "err.test"},
					{IOC: hash, Score: 25, Success: true}, {IOC: "not-hash"},
				},
				Summary: models.RecordSOARResponseSummary{Total: 8, Succeeded: 4, Failed: 4},
			},
			wantEvents: []string{"lookup:192.0.2.1,not-ip", "lookup:example.test,192.0.2.2,err.test", "lookup:" + hash + ",not-hash", "enrich:192.0.2.1", "enrich:192.0.2.1", "enrich:example.test", "enrich:err.test", "enrich:" + hash, "save:192.0.2.1,192.0.2.1,example.test," + hash},
		},
		{
			name:    "save failure preserves result flags and adjusts summary",
			body:    `{"ips":["192.0.2.1"],"incident_id":"test"}`,
			fixture: recordedFutureFixture{scores: map[string]int{"192.0.2.1": 70}, failSave: true},
			status:  http.StatusMultiStatus,
			want: models.RecordSOARBatchResponsePayload{
				Results: []models.RecordSOARResponsePayload{{IOC: "192.0.2.1", Score: 70, Success: true}},
				Summary: models.RecordSOARResponseSummary{Total: 1, Failed: 1},
			},
			wantEvents: []string{"lookup:192.0.2.1", "enrich:192.0.2.1", "save:192.0.2.1"},
		},
		{
			name:    "cache failure stops before further lookups or enrichment",
			body:    `{"ips":["192.0.2.1"],"domains":["example.test"],"hashes":["` + hash + `"],"incident_id":"test"}`,
			fixture: recordedFutureFixture{lookupErrorAt: 2}, status: http.StatusInternalServerError,
			wantEvents: []string{"lookup:192.0.2.1", "lookup:example.test"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			app := tt.fixture.app(t)
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, "/recordedfuture", strings.NewReader(tt.body))
			c.Set("logger", slog.New(slog.NewJSONHandler(io.Discard, nil)))
			app.RecordedFutureSOAR(c)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tt.status, rec.Body.String())
			}
			if !reflect.DeepEqual(tt.fixture.events, tt.wantEvents) {
				t.Errorf("calls = %v, want %v", tt.fixture.events, tt.wantEvents)
			}
			if tt.status == http.StatusInternalServerError {
				if rec.Body.String() != `{"error":"Internal server error"}` {
					t.Errorf("error response = %s", rec.Body.String())
				}
				return
			}
			var got models.RecordSOARBatchResponsePayload
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("response = %#v, want %#v", got, tt.want)
			}
			for _, record := range tt.fixture.written {
				if record.IncidentID != "test" || record.EnrichmentSource != "RecordedFuture" || record.Date != sydneyDate(time.Now()) {
					t.Errorf("written record metadata = %#v", record)
				}
				if want := models.IOCClassifier(record.IOC); record.IOCType != want {
					t.Errorf("written IOC type = %q, want %q", record.IOCType, want)
				}
				if want := string(models.GetMaliciousConfidenceLevel(tt.fixture.scores[record.IOC])); record.MaliciousConfidence != want {
					t.Errorf("written confidence = %q, want %q", record.MaliciousConfidence, want)
				}
			}
		})
	}
}
