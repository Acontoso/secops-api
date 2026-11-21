package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/Acontoso/soar-api/code/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/gin-gonic/gin"
)

const (
	testIOCTable  = "ioc-test-table"
	testSOARTable = "soar-test-table"
)

// failingMarshaler produces a deterministic attributevalue.MarshalMap error.
type failingMarshaler struct{}

func (failingMarshaler) MarshalDynamoDBAttributeValue() (types.AttributeValue, error) {
	return nil, errors.New("marshal boom")
}

type recordedLog struct {
	level   slog.Level
	message string
	attrs   []slog.Attr
}

type recordingHandler struct {
	mu      *sync.Mutex
	entries *[]recordedLog
}

func (h recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h recordingHandler) Handle(_ context.Context, r slog.Record) error {
	entry := recordedLog{level: r.Level, message: r.Message}
	r.Attrs(func(a slog.Attr) bool {
		entry.attrs = append(entry.attrs, a)
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	*h.entries = append(*h.entries, entry)
	return nil
}

func (h recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h recordingHandler) WithGroup(string) slog.Handler      { return h }

func newRecordingLogger() (*slog.Logger, *[]recordedLog) {
	var mu sync.Mutex
	entries := make([]recordedLog, 0)
	return slog.New(recordingHandler{mu: &mu, entries: &entries}), &entries
}

func attrString(entry recordedLog, key string) (string, bool) {
	for _, a := range entry.attrs {
		if a.Key == key {
			return fmt.Sprint(a.Value.Any()), true
		}
	}
	return "", false
}

func findLogs(entries []recordedLog, message string) []recordedLog {
	found := make([]recordedLog, 0)
	for _, entry := range entries {
		if entry.message == message {
			found = append(found, entry)
		}
	}
	return found
}

type loggedRecord struct {
	ioc       string
	secondary string
}

func successRecords(t *testing.T, entries []recordedLog, logKey string) []loggedRecord {
	t.Helper()
	records := make([]loggedRecord, 0)
	for _, entry := range findLogs(entries, "Database record added for IOC") {
		if entry.level != slog.LevelInfo {
			t.Fatalf("success log level = %v, want INFO", entry.level)
		}
		if len(entry.attrs) != 2 || entry.attrs[0].Key != "IOC" || entry.attrs[1].Key != logKey {
			t.Fatalf("success log attrs = %v, want [IOC %s]", entry.attrs, logKey)
		}
		ioc, _ := attrString(entry, "IOC")
		secondary, _ := attrString(entry, logKey)
		records = append(records, loggedRecord{ioc: ioc, secondary: secondary})
	}
	return records
}

func assertNoLogs(t *testing.T, entries []recordedLog, messages ...string) {
	t.Helper()
	for _, message := range messages {
		if logs := findLogs(entries, message); len(logs) != 0 {
			t.Fatalf("unexpected %q logs: %#v", message, logs)
		}
	}
}

func setTestTables(t *testing.T) {
	t.Helper()
	oldIOC, oldSOAR := IOC_TABLE_NAME, SOAR_ACTIONS_TABLE_NAME
	IOC_TABLE_NAME = testIOCTable
	SOAR_ACTIONS_TABLE_NAME = testSOARTable
	t.Cleanup(func() {
		IOC_TABLE_NAME = oldIOC
		SOAR_ACTIONS_TABLE_NAME = oldSOAR
	})
}

func newTestGinContext(t *testing.T) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/test", nil)
	return c
}

type stubBatch struct {
	table string
	items []json.RawMessage
}

// batchWriteStub implements the DynamoDB JSON BatchWriteItem endpoint.
type batchWriteStub struct {
	mu          sync.Mutex
	calls       int
	batches     []stubBatch
	unprocessed map[string][]json.RawMessage
	errStatus   int
	errBody     string
}

func (s *batchWriteStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var request struct {
		RequestItems map[string][]json.RawMessage `json:"RequestItems"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var table string
	var items []json.RawMessage
	for name, requests := range request.RequestItems {
		table = name
		items = requests
	}

	s.mu.Lock()
	s.calls++
	s.batches = append(s.batches, stubBatch{table: table, items: items})
	unprocessed := s.unprocessed[table]
	errStatus, errBody := s.errStatus, s.errBody
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	if errStatus != 0 {
		w.Header().Set("x-amzn-errortype", "ValidationException")
		w.WriteHeader(errStatus)
		_, _ = io.WriteString(w, errBody)
		return
	}

	response := map[string]any{}
	if len(unprocessed) != 0 {
		response["UnprocessedItems"] = map[string][]json.RawMessage{table: unprocessed}
	}
	_ = json.NewEncoder(w).Encode(response)
}

func (s *batchWriteStub) snapshot() (int, []stubBatch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, append([]stubBatch(nil), s.batches...)
}

func newStubClient(t *testing.T, stub *batchWriteStub) *dynamodb.Client {
	t.Helper()
	return newSDKClient(t, stub)
}

// newSDKClient builds a DynamoDB client backed by an in-memory HTTP server
// using static credentials and a NopRetryer, so no live calls or retries occur.
func newSDKClient(t *testing.T, handler http.Handler) *dynamodb.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	cfg := aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("test-key", "test-secret", ""),
		HTTPClient:  server.Client(),
		Retryer:     func() aws.Retryer { return aws.NopRetryer{} },
	}
	return dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String(server.URL)
	})
}

// newTestGinContextWithContext is newTestGinContext with a caller-supplied
// request context, used to exercise cancellation propagation.
func newTestGinContextWithContext(t *testing.T, ctx context.Context) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/test", nil).WithContext(ctx)
	return c
}

// ---- generic DynamoDB JSON wire stubs ----

type dynamoCall struct {
	op   string
	body []byte
}

// dynamoStub serves arbitrary DynamoDB JSON API operations (GetItem, PutItem,
// BatchGetItem, BatchWriteItem, UpdateItem) and records every request.
type dynamoStub struct {
	mu      sync.Mutex
	calls   []dynamoCall
	respond func(op string, body []byte, call int) (status int, resp any)
}

func (s *dynamoStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	op := r.Header.Get("X-Amz-Target")
	if i := strings.LastIndex(op, "."); i >= 0 {
		op = op[i+1:]
	}

	s.mu.Lock()
	call := len(s.calls)
	s.calls = append(s.calls, dynamoCall{op: op, body: body})
	respond := s.respond
	s.mu.Unlock()

	if respond == nil {
		http.Error(w, "no responder configured", http.StatusInternalServerError)
		return
	}

	status, payload := respond(op, body, call)
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	if status != 0 {
		w.Header().Set("x-amzn-errortype", "ValidationException")
		w.WriteHeader(status)
	}
	if raw, ok := payload.(string); ok {
		_, _ = io.WriteString(w, raw)
		return
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *dynamoStub) snapshot() []dynamoCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]dynamoCall(nil), s.calls...)
}

type sdkHTTPFunc func(*http.Request) (*http.Response, error)

func (f sdkHTTPFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

// No socket or default transport is involved: every SDK request reaches f.
func newTransportStubClient(f sdkHTTPFunc) *dynamodb.Client {
	return dynamodb.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("test-key", "test-secret", ""),
		HTTPClient:  f,
		Retryer:     func() aws.Retryer { return aws.NopRetryer{} },
	})
}

func iocItems(n int) []models.IOCTable {
	items := make([]models.IOCTable, n)
	for i := range items {
		items[i] = models.IOCTable{
			IOC:              fmt.Sprintf("ioc-%d", i),
			EnrichmentSource: "src",
		}
	}
	return items
}

func soarItems(n int) []models.SOARTable {
	items := make([]models.SOARTable, n)
	for i := range items {
		items[i] = models.SOARTable{
			IOC:         fmt.Sprintf("ioc-%d", i),
			Integration: "integration",
		}
	}
	return items
}

func TestPutItemsBatchBoundaries(t *testing.T) {
	setTestTables(t)

	cases := []struct {
		name        string
		count       int
		wantBatches []int
	}{
		{name: "zero", count: 0, wantBatches: []int{}},
		{name: "one", count: 1, wantBatches: []int{1}},
		{name: "twenty_four", count: 24, wantBatches: []int{24}},
		{name: "twenty_five", count: 25, wantBatches: []int{25}},
		{name: "twenty_six", count: 26, wantBatches: []int{25, 1}},
		{name: "fifty", count: 50, wantBatches: []int{25, 25}},
		{name: "fifty_one", count: 51, wantBatches: []int{25, 25, 1}},
	}

	kinds := []struct {
		name       string
		table      string
		logKey     string
		secondary  string
		writeItems func(*gin.Context, *dynamodb.Client, *slog.Logger, int) error
	}{
		{
			name:      "IOC",
			table:     testIOCTable,
			logKey:    "Source",
			secondary: "src",
			writeItems: func(c *gin.Context, client *dynamodb.Client, lg *slog.Logger, n int) error {
				return PutItemsIOCFinder(c, client, lg, iocItems(n))
			},
		},
		{
			name:      "SOAR",
			table:     testSOARTable,
			logKey:    "Integration",
			secondary: "integration",
			writeItems: func(c *gin.Context, client *dynamodb.Client, lg *slog.Logger, n int) error {
				return PutItemsSOAR(c, client, lg, soarItems(n))
			},
		},
	}

	for _, kind := range kinds {
		for _, tc := range cases {
			t.Run(kind.name+"/"+tc.name, func(t *testing.T) {
				stub := &batchWriteStub{}
				client := newStubClient(t, stub)
				lg, entries := newRecordingLogger()

				if err := kind.writeItems(newTestGinContext(t), client, lg, tc.count); err != nil {
					t.Fatalf("write items returned error: %v", err)
				}

				calls, batches := stub.snapshot()
				if calls != len(tc.wantBatches) {
					t.Fatalf("BatchWriteItem calls = %d, want %d", calls, len(tc.wantBatches))
				}
				gotBatches := make([]int, len(batches))
				for i, batch := range batches {
					if batch.table != kind.table {
						t.Fatalf("batch %d table = %q, want %q", i, batch.table, kind.table)
					}
					gotBatches[i] = len(batch.items)
				}
				if !reflect.DeepEqual(gotBatches, tc.wantBatches) {
					t.Fatalf("batch sizes = %v, want %v", gotBatches, tc.wantBatches)
				}

				wantRecords := make([]loggedRecord, tc.count)
				for i := range wantRecords {
					wantRecords[i] = loggedRecord{ioc: fmt.Sprintf("ioc-%d", i), secondary: kind.secondary}
				}
				if got := successRecords(t, *entries, kind.logKey); !reflect.DeepEqual(got, wantRecords) {
					t.Fatalf("success logs = %#v, want %#v", got, wantRecords)
				}
				assertNoLogs(t, *entries, "Failed to marshal item", "Couldn't batch write items")
			})
		}
	}
}

func TestPutItemsUnprocessedFiltering(t *testing.T) {
	setTestTables(t)

	t.Run("IOC", func(t *testing.T) {
		stub := &batchWriteStub{
			unprocessed: map[string][]json.RawMessage{
				testIOCTable: {
					json.RawMessage(`{"PutRequest":{"Item":{"IOC":{"S":"ioc-1"},"EnrichmentSource":{"S":"src"}}}}`),
					json.RawMessage(`{"PutRequest":null}`),
					json.RawMessage(`{"PutRequest":{"Item":{"IOC":{"N":"5"},"EnrichmentSource":{"S":"src"}}}}`),
					json.RawMessage(`{"PutRequest":{"Item":{"IOC":{"S":"ioc-4"}}}}`),
				},
			},
		}
		client := newStubClient(t, stub)
		lg, entries := newRecordingLogger()
		items := []models.IOCTable{
			{IOC: "ioc-0", EnrichmentSource: "src"},
			{IOC: "ioc-1", EnrichmentSource: "src"},
			{IOC: "ioc-2", EnrichmentSource: "src"},
			{IOC: "5", EnrichmentSource: "src"},
			{IOC: "ioc-4", EnrichmentSource: "src"},
		}

		// Intentional fix: skipped/unprocessed writes are partial failures,
		// not nil success; valid records and their existing logs are preserved.
		if err := PutItemsIOCFinder(newTestGinContext(t), client, lg, items); err == nil {
			t.Fatal("incomplete batch must return an error")
		}

		calls, batches := stub.snapshot()
		if calls != 1 || len(batches) != 1 || len(batches[0].items) != len(items) {
			t.Fatalf("calls=%d batches=%#v, want one batch with %d items", calls, batches, len(items))
		}

		want := []loggedRecord{
			{ioc: "ioc-0", secondary: "src"},
			{ioc: "ioc-2", secondary: "src"},
			{ioc: "5", secondary: "src"},
			{ioc: "ioc-4", secondary: "src"},
		}
		if got := successRecords(t, *entries, "Source"); !reflect.DeepEqual(got, want) {
			t.Fatalf("success logs = %#v, want %#v", got, want)
		}
	})

	t.Run("SOAR", func(t *testing.T) {
		stub := &batchWriteStub{
			unprocessed: map[string][]json.RawMessage{
				testSOARTable: {
					json.RawMessage(`{"PutRequest":{"Item":{"IOC":{"S":"ioc-1"},"Integration":{"S":"integration"}}}}`),
					json.RawMessage(`{"PutRequest":null}`),
					json.RawMessage(`{"PutRequest":{"Item":{"IOC":{"N":"5"},"Integration":{"S":"integration"}}}}`),
					json.RawMessage(`{"PutRequest":{"Item":{"IOC":{"S":"ioc-4"}}}}`),
				},
			},
		}
		client := newStubClient(t, stub)
		lg, entries := newRecordingLogger()
		items := []models.SOARTable{
			{IOC: "ioc-0", Integration: "integration"},
			{IOC: "ioc-1", Integration: "integration"},
			{IOC: "ioc-2", Integration: "integration"},
			{IOC: "5", Integration: "integration"},
			{IOC: "ioc-4", Integration: "integration"},
		}

		// Intentional fix: skipped/unprocessed writes are partial failures,
		// not nil success; valid records and their existing logs are preserved.
		if err := PutItemsSOAR(newTestGinContext(t), client, lg, items); err == nil {
			t.Fatal("incomplete batch must return an error")
		}

		calls, batches := stub.snapshot()
		if calls != 1 || len(batches) != 1 || len(batches[0].items) != len(items) {
			t.Fatalf("calls=%d batches=%#v, want one batch with %d items", calls, batches, len(items))
		}

		want := []loggedRecord{
			{ioc: "ioc-0", secondary: "integration"},
			{ioc: "ioc-2", secondary: "integration"},
			{ioc: "5", secondary: "integration"},
			{ioc: "ioc-4", secondary: "integration"},
		}
		if got := successRecords(t, *entries, "Integration"); !reflect.DeepEqual(got, want) {
			t.Fatalf("success logs = %#v, want %#v", got, want)
		}
	})
}

func TestPutItemsMarshalFailureSkipsItem(t *testing.T) {
	setTestTables(t)

	t.Run("IOC", func(t *testing.T) {
		stub := &batchWriteStub{}
		client := newStubClient(t, stub)
		lg, entries := newRecordingLogger()
		items := []models.IOCTable{
			{IOC: "ioc-0", EnrichmentSource: "src"},
			{IOC: "ioc-bad", EnrichmentSource: "src", Info: map[string]interface{}{"bad": failingMarshaler{}}},
			{IOC: "ioc-2", EnrichmentSource: "src"},
		}

		// Intentional fix: skipped/unprocessed writes are partial failures,
		// not nil success; valid records and their existing logs are preserved.
		if err := PutItemsIOCFinder(newTestGinContext(t), client, lg, items); err == nil {
			t.Fatal("incomplete batch must return an error")
		}

		calls, batches := stub.snapshot()
		if calls != 1 || len(batches) != 1 || len(batches[0].items) != 2 {
			t.Fatalf("calls=%d batches=%#v, want one batch with 2 items", calls, batches)
		}

		failures := findLogs(*entries, "Failed to marshal item")
		if len(failures) != 1 {
			t.Fatalf("marshal failure logs = %d, want 1", len(failures))
		}
		if len(failures[0].attrs) != 1 || failures[0].attrs[0].Key != "error" {
			t.Fatalf("marshal failure attrs = %v, want [error]", failures[0].attrs)
		}

		want := []loggedRecord{
			{ioc: "ioc-0", secondary: "src"},
			{ioc: "ioc-2", secondary: "src"},
		}
		if got := successRecords(t, *entries, "Source"); !reflect.DeepEqual(got, want) {
			t.Fatalf("success logs = %#v, want %#v", got, want)
		}

		// The marshal failure is logged while building the batch, before the write succeeds.
		successIndex := -1
		for i, entry := range *entries {
			if entry.message == "Database record added for IOC" {
				successIndex = i
				break
			}
		}
		failureIndex := -1
		for i, entry := range *entries {
			if entry.message == "Failed to marshal item" {
				failureIndex = i
				break
			}
		}
		if failureIndex == -1 || successIndex == -1 || failureIndex > successIndex {
			t.Fatalf("log order = %#v, want marshal failure before success logs", *entries)
		}
	})

	t.Run("SOAR", func(t *testing.T) {
		stub := &batchWriteStub{}
		client := newStubClient(t, stub)
		lg, entries := newRecordingLogger()
		items := []models.SOARTable{
			{IOC: "ioc-0", Integration: "integration"},
			{IOC: "ioc-bad", Integration: "integration", Info: map[string]interface{}{"bad": failingMarshaler{}}},
			{IOC: "ioc-2", Integration: "integration"},
		}

		// Intentional fix: skipped/unprocessed writes are partial failures,
		// not nil success; valid records and their existing logs are preserved.
		if err := PutItemsSOAR(newTestGinContext(t), client, lg, items); err == nil {
			t.Fatal("incomplete batch must return an error")
		}

		calls, batches := stub.snapshot()
		if calls != 1 || len(batches) != 1 || len(batches[0].items) != 2 {
			t.Fatalf("calls=%d batches=%#v, want one batch with 2 items", calls, batches)
		}

		if failures := findLogs(*entries, "Failed to marshal item"); len(failures) != 1 {
			t.Fatalf("marshal failure logs = %d, want 1", len(failures))
		}

		want := []loggedRecord{
			{ioc: "ioc-0", secondary: "integration"},
			{ioc: "ioc-2", secondary: "integration"},
		}
		if got := successRecords(t, *entries, "Integration"); !reflect.DeepEqual(got, want) {
			t.Fatalf("success logs = %#v, want %#v", got, want)
		}
	})
}

func TestPutItemsNilClient(t *testing.T) {
	setTestTables(t)

	t.Run("IOC", func(t *testing.T) {
		lg, entries := newRecordingLogger()
		err := PutItemsIOCFinder(newTestGinContext(t), nil, lg, iocItems(1))
		if !errors.Is(err, ErrNoDBClient) {
			t.Fatalf("error = %v, want ErrNoDBClient", err)
		}
		assertNilClientLog(t, *entries)
	})

	t.Run("SOAR", func(t *testing.T) {
		lg, entries := newRecordingLogger()
		err := PutItemsSOAR(newTestGinContext(t), nil, lg, soarItems(1))
		if !errors.Is(err, ErrNoDBClient) {
			t.Fatalf("error = %v, want ErrNoDBClient", err)
		}
		assertNilClientLog(t, *entries)
	})
}

func assertNilClientLog(t *testing.T, entries []recordedLog) {
	t.Helper()
	logs := findLogs(entries, "dynamodb client is nil")
	if len(logs) != 1 {
		t.Fatalf("nil client logs = %d, want 1: %#v", len(logs), entries)
	}
	if logs[0].level != slog.LevelError || len(logs[0].attrs) != 0 {
		t.Fatalf("nil client log = %#v, want one ERROR without attrs", logs[0])
	}
}

func TestPutItemsSDKErrorReturnsImmediately(t *testing.T) {
	setTestTables(t)

	kinds := []struct {
		name string
		run  func(*gin.Context, *dynamodb.Client, *slog.Logger) error
	}{
		{
			name: "IOC",
			run: func(c *gin.Context, client *dynamodb.Client, lg *slog.Logger) error {
				// 26 items span two batches; the first error must stop all further writes.
				return PutItemsIOCFinder(c, client, lg, iocItems(26))
			},
		},
		{
			name: "SOAR",
			run: func(c *gin.Context, client *dynamodb.Client, lg *slog.Logger) error {
				return PutItemsSOAR(c, client, lg, soarItems(26))
			},
		},
	}

	for _, kind := range kinds {
		t.Run(kind.name, func(t *testing.T) {
			stub := &batchWriteStub{
				errStatus: http.StatusBadRequest,
				errBody:   `{"__type":"com.amazonaws.dynamodb.v20120810#ValidationException","message":"boom"}`,
			}
			client := newStubClient(t, stub)
			lg, entries := newRecordingLogger()

			err := kind.run(newTestGinContext(t), client, lg)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}

			calls, _ := stub.snapshot()
			if calls != 1 {
				t.Fatalf("BatchWriteItem calls = %d, want 1 (no retry, immediate return)", calls)
			}

			errorLogs := findLogs(*entries, "Couldn't batch write items")
			if len(errorLogs) != 1 {
				t.Fatalf("batch error logs = %d, want 1: %#v", len(errorLogs), *entries)
			}
			if errorLogs[0].level != slog.LevelError || len(errorLogs[0].attrs) != 1 || errorLogs[0].attrs[0].Key != "error" {
				t.Fatalf("batch error log = %#v, want one ERROR with error attr", errorLogs[0])
			}
			assertNoLogs(t, *entries, "Database record added for IOC", "Failed to marshal item")
		})
	}
}
