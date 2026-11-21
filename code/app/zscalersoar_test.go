package app

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/Acontoso/soar-api/code/database"
	"github.com/Acontoso/soar-api/code/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/gin-gonic/gin"
)

func TestBlockZscalerIOCs(t *testing.T) {
	oldTable := database.SOAR_ACTIONS_TABLE_NAME
	database.SOAR_ACTIONS_TABLE_NAME = "soar-test"
	t.Cleanup(func() { database.SOAR_ACTIONS_TABLE_NAME = oldTable })

	for _, tt := range []struct {
		name string
		iocs []string
		want models.SSEUploadSummary
	}{
		{name: "nil input retains nil results"},
		{name: "empty input retains nil results", iocs: []string{}},
		{name: "all cached", iocs: []string{"cached-a", "cached-b"}, want: models.SSEUploadSummary{Total: 2, Succeeded: 2}},
		{name: "mixed errors", iocs: []string{"cached-a", "error", "cached-b"}, want: models.SSEUploadSummary{Total: 3, Succeeded: 2, Failed: 1}},
		{name: "duplicate IOCs are processed individually", iocs: []string{"cached-a", "cached-a"}, want: models.SSEUploadSummary{Total: 2, Succeeded: 2}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var calls []string
			transport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				if got := r.Header.Get("X-Amz-Target"); got != "DynamoDB_20120810.GetItem" {
					t.Errorf("unexpected external operation %q", got)
				}
				var input struct{ Key map[string]struct{ S string } }
				if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
					return nil, err
				}
				ioc := input.Key["IOC"].S
				mu.Lock()
				calls = append(calls, ioc)
				mu.Unlock()
				if ioc == "error" {
					return jsonHTTPResponse(http.StatusBadRequest, map[string]string{"__type": "ValidationException", "message": "lookup failed"})
				}
				return jsonHTTPResponse(http.StatusOK, map[string]any{"Item": map[string]any{
					"IOC": map[string]string{"S": ioc}, "Integration": map[string]string{"S": "Zscaler"},
				}})
			})
			client := dynamodb.NewFromConfig(aws.Config{
				Region: "ap-southeast-2", HTTPClient: &http.Client{Transport: transport},
				Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
				Retryer:     func() aws.Retryer { return aws.NopRetryer{} },
			})
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/zscaler", nil)
			lg := slog.New(slog.NewJSONHandler(io.Discard, nil))
			got := (&App{Dynamo: client}).blockZscalerIOCs(c, tt.iocs, "test", "unused-token", lg)
			if got.Summary != tt.want {
				t.Errorf("summary = %#v, want %#v", got.Summary, tt.want)
			}
			var wantResults []models.SSEUploadResponsePayload
			for _, ioc := range tt.iocs {
				response := models.SSEUploadResponsePayload{IOC: ioc, Integration: "Zscaler", Added: true, Action: "Block"}
				if ioc == "error" {
					response.Added, response.Action = false, "Failed"
				}
				wantResults = append(wantResults, response)
			}
			// Workers intentionally return completion order; compare membership,
			// not a deterministic ordering that the endpoint does not promise.
			sort.Slice(got.Results, func(i, j int) bool { return got.Results[i].IOC < got.Results[j].IOC })
			sort.Slice(wantResults, func(i, j int) bool { return wantResults[i].IOC < wantResults[j].IOC })
			if !reflect.DeepEqual(got.Results, wantResults) {
				t.Errorf("results = %#v, want %#v", got.Results, wantResults)
			}
			mu.Lock()
			gotCalls := append([]string(nil), calls...)
			mu.Unlock()
			wantCalls := append([]string(nil), tt.iocs...)
			sort.Strings(gotCalls)
			sort.Strings(wantCalls)
			if !reflect.DeepEqual(gotCalls, wantCalls) {
				t.Errorf("lookups = %v, want %v", gotCalls, wantCalls)
			}
		})
	}
}
