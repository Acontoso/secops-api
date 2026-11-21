package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Acontoso/soar-api/code/models"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/gin-gonic/gin"
)

// Run the same public-operation contracts against both table schemas.
type databaseContract struct {
	name, table, secondary string
	get                    func(*gin.Context, *dynamodb.Client, *slog.Logger) (any, error)
	batchGet               func(*gin.Context, *dynamodb.Client, []string, *slog.Logger) (any, error)
	put                    func(*gin.Context, *dynamodb.Client, *slog.Logger, map[string]interface{}, bool) error
	batchPut               func(*gin.Context, *dynamodb.Client, *slog.Logger, int, map[string]interface{}) error
}

func databaseContracts() []databaseContract {
	return []databaseContract{
		{"IOC", testIOCTable, "EnrichmentSource",
			func(c *gin.Context, d *dynamodb.Client, l *slog.Logger) (any, error) {
				v, e := GetItemIOCFinder(c, d, "ioc-0", "src", l)
				return v, e
			},
			func(c *gin.Context, d *dynamodb.Client, k []string, l *slog.Logger) (any, error) {
				return GetItemsIOCFinder(c, d, k, "src", l)
			},
			func(c *gin.Context, d *dynamodb.Client, l *slog.Logger, info map[string]interface{}, nilData bool) error {
				var v *models.IOCTable
				if !nilData {
					v = &models.IOCTable{IOC: "ioc-0", EnrichmentSource: "src", IOCType: "IPv4", IncidentID: "incident", MaliciousConfidence: "High", Date: "today", Info: info}
				}
				return PutItemIOCFinder(c, d, l, v)
			},
			func(c *gin.Context, d *dynamodb.Client, l *slog.Logger, n int, info map[string]interface{}) error {
				v := iocItems(n)
				for i := range v {
					v[i].Info = info
				}
				return PutItemsIOCFinder(c, d, l, v)
			}},
		{"SOAR", testSOARTable, "Integration",
			func(c *gin.Context, d *dynamodb.Client, l *slog.Logger) (any, error) {
				v, e := GetItemSOAR(c, d, "ioc-0", "src", l)
				return v, e
			},
			func(c *gin.Context, d *dynamodb.Client, k []string, l *slog.Logger) (any, error) {
				return GetItemsSOAR(c, d, k, "src", l)
			},
			func(c *gin.Context, d *dynamodb.Client, l *slog.Logger, info map[string]interface{}, nilData bool) error {
				var v *models.SOARTable
				if !nilData {
					v = &models.SOARTable{IOC: "ioc-0", Integration: "src", IncidentID: "incident", Date: "today", Info: info}
				}
				return PutItemSOAR(c, d, l, v)
			},
			func(c *gin.Context, d *dynamodb.Client, l *slog.Logger, n int, info map[string]interface{}) error {
				v := soarItems(n)
				for i := range v {
					v[i].Info = info
				}
				return PutItemsSOAR(c, d, l, v)
			}},
	}
}
func wireKey(secondary, ioc string) map[string]any {
	return map[string]any{"IOC": map[string]any{"S": ioc}, secondary: map[string]any{"S": "src"}}
}
func wireRecord(secondary, ioc string) map[string]any {
	v := wireKey(secondary, ioc)
	v["Date"] = map[string]any{"S": "today"}
	v["IncidentID"] = map[string]any{"S": "incident"}
	v["Info"] = map[string]any{"M": map[string]any{"score": map[string]any{"N": "42"}, "Accounts": map[string]any{"L": []any{map[string]any{"S": "account"}}}}}
	if secondary == "EnrichmentSource" {
		v["IOCType"] = map[string]any{"S": "IPv4"}
		v["MaliciousConfidence"] = map[string]any{"S": "High"}
	}
	return v
}
func decodeWire(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if e := json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func resultLen(v any) int {
	r := reflect.ValueOf(v)
	if !r.IsValid() {
		return 0
	}
	return r.Len()
}
func assertRecord(t *testing.T, v any) {
	t.Helper()
	r := reflect.Indirect(reflect.ValueOf(v))
	if r.FieldByName("IOC").String() != "ioc-0" || r.FieldByName("Date").String() != "today" || r.FieldByName("IncidentID").String() != "incident" {
		t.Fatalf("record = %#v", v)
	}
	info := r.FieldByName("Info").Interface().(map[string]interface{})
	// The installed default attributevalue decoder uses float64, not int64.
	if info["score"] != float64(42) || !reflect.DeepEqual(info["Accounts"], []interface{}{"account"}) {
		t.Fatalf("Info = %#v", info)
	}
}

const sdkErrorBody = `{"__type":"com.amazonaws.dynamodb.v20120810#ValidationException","message":"boom"}`

func TestSingleGetContracts(t *testing.T) {
	setTestTables(t)
	for _, kind := range databaseContracts() {
		t.Run(kind.name, func(t *testing.T) {
			for _, scenario := range []string{"success", "missing", "empty", "malformed", "sdk_error", "bad_json", "nil_client", "cancelled"} {
				t.Run(scenario, func(t *testing.T) {
					stub := &dynamoStub{respond: func(op string, b []byte, _ int) (int, any) {
						if op != "GetItem" {
							t.Errorf("operation = %s", op)
						}
						want := map[string]any{"TableName": kind.table, "Key": wireKey(kind.secondary, "ioc-0")}
						if got := decodeWire(t, b); !reflect.DeepEqual(got, want) {
							t.Errorf("request = %#v, want %#v", got, want)
						}
						switch scenario {
						case "missing":
							return 0, map[string]any{}
						case "empty":
							return 0, map[string]any{"Item": map[string]any{}}
						case "malformed":
							return 0, map[string]any{"Item": map[string]any{"Info": map[string]any{"S": "not a map"}}}
						case "sdk_error":
							return 400, sdkErrorBody
						case "bad_json":
							return 0, "{"
						}
						return 0, map[string]any{"Item": wireRecord(kind.secondary, "ioc-0")}
					}}
					client := newSDKClient(t, stub)
					lg, logs := newRecordingLogger()
					c := newTestGinContext(t)
					if scenario == "nil_client" {
						client = nil
					}
					if scenario == "cancelled" {
						ctx, cancel := context.WithCancel(context.Background())
						cancel()
						c = newTestGinContextWithContext(t, ctx)
					}
					got, err := kind.get(c, client, lg)
					switch scenario {
					case "success":
						if err != nil {
							t.Fatal(err)
						}
						assertRecord(t, got)
					case "missing", "empty":
						if !errors.Is(err, ErrNotFound) {
							t.Fatalf("error = %v", err)
						}
					case "nil_client":
						if !errors.Is(err, ErrNoDBClient) {
							t.Fatalf("error = %v", err)
						}
						assertNilClientLog(t, *logs)
					case "cancelled":
						if !errors.Is(err, context.Canceled) {
							t.Fatalf("error = %v", err)
						}
					default:
						if err == nil {
							t.Fatal("expected error")
						}
					}
					if scenario != "success" && !reflect.ValueOf(got).IsNil() {
						t.Fatalf("failed get returned %#v", got)
					}
					if scenario == "nil_client" || scenario == "cancelled" {
						if len(stub.snapshot()) != 0 {
							t.Fatal("unexpected outbound call")
						}
					}
				})
			}
		})
	}
}

func TestSinglePutContracts(t *testing.T) {
	setTestTables(t)
	for _, kind := range databaseContracts() {
		t.Run(kind.name, func(t *testing.T) {
			for _, scenario := range []string{"success", "sdk_error", "bad_json", "marshal_error", "nil_data", "nil_client", "cancelled"} {
				t.Run(scenario, func(t *testing.T) {
					stub := &dynamoStub{respond: func(op string, b []byte, _ int) (int, any) {
						if op != "PutItem" {
							t.Errorf("operation = %s", op)
						}
						want := map[string]any{"TableName": kind.table, "Item": wireRecord(kind.secondary, "ioc-0")}
						if got := decodeWire(t, b); !reflect.DeepEqual(got, want) {
							t.Errorf("request = %#v, want %#v", got, want)
						}
						if scenario == "sdk_error" {
							return 400, sdkErrorBody
						}
						if scenario == "bad_json" {
							return 0, "{"
						}
						return 0, map[string]any{}
					}}
					client := newSDKClient(t, stub)
					lg, logs := newRecordingLogger()
					c := newTestGinContext(t)
					info := map[string]interface{}{"score": float64(42), "Accounts": []string{"account"}}
					if scenario == "marshal_error" {
						info = map[string]interface{}{"bad": failingMarshaler{}}
					}
					if scenario == "nil_client" {
						client = nil
					}
					if scenario == "cancelled" {
						ctx, cancel := context.WithCancel(context.Background())
						cancel()
						c = newTestGinContextWithContext(t, ctx)
					}
					err := kind.put(c, client, lg, info, scenario == "nil_data")
					if scenario == "success" {
						if err != nil {
							t.Fatal(err)
						}
						if len(findLogs(*logs, "Database record added for IOC")) != 1 {
							t.Fatal("missing success log")
						}
					} else {
						if err == nil {
							t.Fatal("expected error")
						}
						assertNoLogs(t, *logs, "Database record added for IOC")
					}
					if scenario == "marshal_error" && !strings.Contains(err.Error(), "marshal boom") {
						t.Fatalf("error = %v", err)
					}
					if scenario == "nil_client" && !errors.Is(err, ErrNoDBClient) {
						t.Fatalf("error = %v", err)
					}
					if scenario == "cancelled" && !errors.Is(err, context.Canceled) {
						t.Fatalf("error = %v", err)
					}
					if scenario == "nil_client" || scenario == "nil_data" || scenario == "marshal_error" || scenario == "cancelled" {
						if len(stub.snapshot()) != 0 {
							t.Fatal("unexpected outbound call")
						}
					}
				})
			}
		})
	}
}

func TestBatchGetBoundariesAndDuplicates(t *testing.T) {
	setTestTables(t)
	for _, kind := range databaseContracts() {
		t.Run(kind.name, func(t *testing.T) {
			for _, n := range []int{0, 1, 100, 101, 201} {
				t.Run(fmt.Sprint(n), func(t *testing.T) {
					keys := make([]string, n)
					for i := range keys {
						keys[i] = fmt.Sprintf("ioc-%d", i)
					}
					// Include duplicates both adjacent and crossing chunk boundaries.
					input := append([]string{}, keys...)
					input = append(input, keys...)
					stub := &dynamoStub{respond: func(op string, b []byte, call int) (int, any) {
						if op != "BatchGetItem" {
							t.Errorf("operation = %s", op)
						}
						req := decodeWire(t, b)["RequestItems"].(map[string]any)
						if len(req) != 1 {
							t.Errorf("request tables = %v", req)
						}
						attrs := req[kind.table].(map[string]any)
						got := attrs["Keys"].([]any)
						start := call * 100
						end := min(start+100, n)
						if len(got) != end-start {
							t.Errorf("chunk size = %d, want %d", len(got), end-start)
							return 400, sdkErrorBody
						}
						records := make([]any, 0, len(got))
						for i, k := range got {
							if !reflect.DeepEqual(k, wireKey(kind.secondary, keys[start+i])) {
								t.Errorf("key = %#v", k)
							}
							records = append(records, wireRecord(kind.secondary, keys[start+i]))
						}
						return 0, map[string]any{"Responses": map[string]any{kind.table: records}}
					}}
					lg, _ := newRecordingLogger()
					got, err := kind.batchGet(newTestGinContext(t), newSDKClient(t, stub), input, lg)
					if n == 0 {
						if !errors.Is(err, ErrNotFound) {
							t.Fatalf("error = %v", err)
						}
					} else if err != nil {
						t.Fatal(err)
					}
					if resultLen(got) != n || len(stub.snapshot()) != (n+99)/100 {
						t.Fatalf("results = %d calls = %d", resultLen(got), len(stub.snapshot()))
					}
					// Results retain service response order; no input-order promise is added.
					for i := 0; i < n; i++ {
						v := reflect.ValueOf(got).Index(i)
						if v.FieldByName("IOC").String() != keys[i] {
							t.Fatal("wrong result order")
						}
					}
				})
			}
		})
	}
}

func TestBatchGetResponseContracts(t *testing.T) {
	setTestTables(t)
	for _, kind := range databaseContracts() {
		t.Run(kind.name, func(t *testing.T) {
			for _, scenario := range []string{"missing", "empty_table", "other_table", "cache_miss", "unprocessed", "unprocessed_only", "malformed", "all_malformed", "sdk_error", "later_error", "bad_json", "nil_client", "cancelled"} {
				t.Run(scenario, func(t *testing.T) {
					keys := []string{"ioc-0", "ioc-1"}
					if scenario == "later_error" {
						keys = make([]string, 101)
						for i := range keys {
							keys[i] = fmt.Sprintf("ioc-%d", i)
						}
					}
					stub := &dynamoStub{respond: func(_ string, _ []byte, call int) (int, any) {
						switch scenario {
						case "missing":
							return 0, map[string]any{}
						case "empty_table":
							return 0, map[string]any{"Responses": map[string]any{kind.table: []any{}}}
						case "other_table":
							return 0, map[string]any{"Responses": map[string]any{"other": []any{wireRecord(kind.secondary, "ioc-0")}}}
						case "sdk_error":
							return 400, sdkErrorBody
						case "later_error":
							if call == 1 {
								return 400, sdkErrorBody
							}
						case "bad_json":
							return 0, "{"
						}
						records := []any{wireRecord(kind.secondary, "ioc-0")}
						if scenario == "malformed" || scenario == "all_malformed" {
							bad := map[string]any{"Info": map[string]any{"S": "not a map"}}
							if scenario == "all_malformed" {
								records = []any{bad}
							} else {
								records = append(records, bad)
							}
						}
						response := map[string]any{"Responses": map[string]any{kind.table: records}}
						if scenario == "unprocessed" || scenario == "unprocessed_only" {
							response["UnprocessedKeys"] = map[string]any{kind.table: map[string]any{"Keys": []any{wireKey(kind.secondary, "ioc-1")}}}
							if scenario == "unprocessed_only" {
								delete(response, "Responses")
							}
						}
						return 0, response
					}}
					client := newSDKClient(t, stub)
					lg, _ := newRecordingLogger()
					c := newTestGinContext(t)
					if scenario == "nil_client" {
						client = nil
					}
					if scenario == "cancelled" {
						ctx, cancel := context.WithCancel(context.Background())
						cancel()
						c = newTestGinContextWithContext(t, ctx)
					}
					got, err := kind.batchGet(c, client, keys, lg)
					switch scenario {
					case "missing", "empty_table", "other_table":
						if !errors.Is(err, ErrNotFound) || resultLen(got) != 0 {
							t.Fatalf("results = %#v error = %v", got, err)
						}
					case "cache_miss":
						if err != nil || resultLen(got) != 1 {
							t.Fatalf("results = %#v error = %v", got, err)
						}
					case "unprocessed", "unprocessed_only":
						if err == nil || errors.Is(err, ErrNotFound) {
							t.Fatalf("error = %v", err)
						}
					case "nil_client":
						if !errors.Is(err, ErrNoDBClient) {
							t.Fatalf("error = %v", err)
						}
					case "cancelled":
						if !errors.Is(err, context.Canceled) {
							t.Fatalf("error = %v", err)
						}
					default:
						if err == nil {
							t.Fatal("expected error")
						}
					}
					if scenario == "later_error" || scenario == "malformed" || scenario == "unprocessed" {
						if resultLen(got) != 1 {
							t.Fatalf("partial results = %#v", got)
						}
					}
					if scenario == "later_error" && len(stub.snapshot()) != 2 {
						t.Fatal("expected exactly two calls")
					}
				})
			}
		})
	}
}

func TestUpdateAccountsContracts(t *testing.T) {
	setTestTables(t)
	for _, scenario := range []string{"success", "sdk_error", "bad_json", "nil_client", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			stub := &dynamoStub{respond: func(op string, b []byte, _ int) (int, any) {
				if op != "UpdateItem" {
					t.Errorf("operation = %s", op)
				}
				want := map[string]any{"TableName": testSOARTable, "Key": wireKey("Integration", "ioc-0"), "UpdateExpression": "SET Info.Accounts = list_append(if_not_exists(Info.Accounts, :empty_list), :new_account)", "ExpressionAttributeValues": map[string]any{":new_account": map[string]any{"L": []any{map[string]any{"S": "account"}}}, ":empty_list": map[string]any{"L": []any{}}}}
				if got := decodeWire(t, b); !reflect.DeepEqual(got, want) {
					t.Errorf("request = %#v, want %#v", got, want)
				}
				if scenario == "sdk_error" {
					return 400, sdkErrorBody
				}
				if scenario == "bad_json" {
					return 0, "{"
				}
				return 0, map[string]any{}
			}}
			client := newSDKClient(t, stub)
			lg, logs := newRecordingLogger()
			c := newTestGinContext(t)
			if scenario == "nil_client" {
				client = nil
			}
			if scenario == "cancelled" {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				c = newTestGinContextWithContext(t, ctx)
			}
			err := UpdateItemSOARAccounts(c, client, lg, "ioc-0", "src", "account")
			if scenario == "success" {
				if err != nil {
					t.Fatal(err)
				}
				if len(findLogs(*logs, "Database record updated for SOAR action")) != 1 {
					t.Fatal("missing success log")
				}
			} else {
				if err == nil {
					t.Fatal("expected error")
				}
				assertNoLogs(t, *logs, "Database record updated for SOAR action")
			}
			if scenario == "nil_client" && !errors.Is(err, ErrNoDBClient) {
				t.Fatalf("error = %v", err)
			}
			if scenario == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestBatchWritePayloadContracts(t *testing.T) {
	setTestTables(t)
	for _, kind := range databaseContracts() {
		t.Run(kind.name, func(t *testing.T) {
			stub := &dynamoStub{respond: func(op string, b []byte, _ int) (int, any) {
				if op != "BatchWriteItem" {
					t.Errorf("operation = %s", op)
				}
				record := wireRecord(kind.secondary, "ioc-0")
				for key := range record {
					if key != "IOC" && key != kind.secondary && key != "Info" {
						record[key] = map[string]any{"S": ""}
					}
				}
				if kind.name == "SOAR" {
					record[kind.secondary] = map[string]any{"S": "integration"}
				}
				want := map[string]any{"RequestItems": map[string]any{kind.table: []any{map[string]any{"PutRequest": map[string]any{"Item": record}}}}}
				if got := decodeWire(t, b); !reflect.DeepEqual(got, want) {
					t.Errorf("request = %#v, want %#v", got, want)
				}
				return 0, map[string]any{}
			}}
			lg, _ := newRecordingLogger()
			if err := kind.batchPut(newTestGinContext(t), newSDKClient(t, stub), lg, 1, map[string]interface{}{"score": float64(42), "Accounts": []string{"account"}}); err != nil {
				t.Fatal(err)
			}
			if len(stub.snapshot()) != 1 {
				t.Fatal("expected one request")
			}
		})
	}
}

func TestBatchWritePartialFailureRegression(t *testing.T) {
	setTestTables(t)
	for _, kind := range databaseContracts() {
		t.Run(kind.name, func(t *testing.T) {
			for _, scenario := range []string{"skipped", "unprocessed", "sdk_error", "later_error", "bad_json", "cancelled"} {
				t.Run(scenario, func(t *testing.T) {
					stub := &dynamoStub{respond: func(op string, b []byte, call int) (int, any) {
						if op != "BatchWriteItem" {
							t.Errorf("operation = %s", op)
						}
						switch scenario {
						case "sdk_error":
							return 400, sdkErrorBody
						case "later_error":
							if call == 1 {
								return 400, sdkErrorBody
							}
						case "bad_json":
							return 0, "{"
						case "unprocessed":
							return 0, map[string]any{"UnprocessedItems": decodeWire(t, b)["RequestItems"]}
						}
						return 0, map[string]any{}
					}}
					lg, logs := newRecordingLogger()
					c := newTestGinContext(t)
					var info map[string]interface{}
					n := 1
					if scenario == "skipped" {
						info = map[string]interface{}{"bad": failingMarshaler{}}
					}
					if scenario == "later_error" {
						n = 51
					}
					if scenario == "cancelled" {
						ctx, cancel := context.WithCancel(context.Background())
						cancel()
						c = newTestGinContextWithContext(t, ctx)
					}
					err := kind.batchPut(c, newSDKClient(t, stub), lg, n, info)
					if err == nil {
						t.Fatal("incomplete batch must not return nil success")
					}
					if scenario == "cancelled" && !errors.Is(err, context.Canceled) {
						t.Fatalf("error = %v", err)
					}
					if scenario == "skipped" && len(stub.snapshot()) != 0 {
						t.Fatal("all-skipped batch should not call SDK")
					}
					if scenario == "unprocessed" {
						assertNoLogs(t, *logs, "Database record added for IOC")
					}
					if scenario == "later_error" && (len(stub.snapshot()) != 2 || len(findLogs(*logs, "Database record added for IOC")) != 25) {
						t.Fatal("must preserve successful first batch and stop at second")
					}
				})
			}
		})
	}
}

// A truncated later-chunk body surfaces as an SDK decode error while keeping
// the valid records returned by earlier chunks.
func TestBatchGetMalformedChunkTerminates(t *testing.T) {
	setTestTables(t)
	stub := &dynamoStub{respond: func(_ string, _ []byte, call int) (int, any) {
		if call == 1 {
			// Second chunk: valid headers, truncated body.
			return 0, `{"Responses":{"` + testSOARTable + `":[`
		}
		return 0, map[string]any{"Responses": map[string]any{testSOARTable: []any{wireRecord("Integration", "ioc-0")}}}
	}}
	client := newSDKClient(t, stub)
	lg, _ := newRecordingLogger()

	iocs := make([]string, 101)
	for i := range iocs {
		iocs[i] = fmt.Sprintf("ioc-%d", i)
	}
	results, err := GetItemsSOAR(newTestGinContext(t), client, iocs, "src", lg)
	if err == nil {
		t.Fatal("malformed chunk must return an error")
	}
	if len(results) != 1 || results[0].IOC != "ioc-0" {
		t.Fatalf("partial results = %#v, want the valid first-chunk record", results)
	}
}

func TestOperationsCancelInFlight(t *testing.T) {
	setTestTables(t)
	for _, kind := range databaseContracts() {
		t.Run(kind.name, func(t *testing.T) {
			operations := map[string]func(*gin.Context, *dynamodb.Client, *slog.Logger) error{
				"get": func(c *gin.Context, d *dynamodb.Client, l *slog.Logger) error {
					_, err := kind.get(c, d, l)
					return err
				},
				"batch_get": func(c *gin.Context, d *dynamodb.Client, l *slog.Logger) error {
					_, err := kind.batchGet(c, d, []string{"ioc-0"}, l)
					return err
				},
				"put":       func(c *gin.Context, d *dynamodb.Client, l *slog.Logger) error { return kind.put(c, d, l, nil, false) },
				"batch_put": func(c *gin.Context, d *dynamodb.Client, l *slog.Logger) error { return kind.batchPut(c, d, l, 26, nil) },
			}
			if kind.name == "SOAR" {
				operations["update"] = func(c *gin.Context, d *dynamodb.Client, l *slog.Logger) error {
					return UpdateItemSOARAccounts(c, d, l, "ioc-0", "src", "account")
				}
			}
			for name, operation := range operations {
				t.Run(name, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					calls := 0
					client := newTransportStubClient(func(r *http.Request) (*http.Response, error) {
						calls++
						if _, ok := r.Context().Deadline(); !ok {
							t.Error("SDK request has no deadline")
						}
						cancel()
						<-r.Context().Done()
						return nil, r.Context().Err()
					})
					lg, logs := newRecordingLogger()
					err := operation(newTestGinContextWithContext(t, ctx), client, lg)
					if !errors.Is(err, context.Canceled) || calls != 1 {
						t.Fatalf("error = %v, calls = %d", err, calls)
					}
					assertNoLogs(t, *logs, "Database record added for IOC", "Database record updated for SOAR action", "Database hit for IOC")
				})
			}
		})
	}
}

func TestNewDynamoDBClientOffline(t *testing.T) {
	// Isolate shared config and credentials from the developer's workstation and
	// disable metadata discovery. Constructing the client must require no network.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte("[default]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"AWS_EC2_METADATA_DISABLED": "true", "AWS_ACCESS_KEY_ID": "test-key", "AWS_SECRET_ACCESS_KEY": "test-secret", "AWS_SESSION_TOKEN": "", "AWS_PROFILE": "default", "AWS_DEFAULT_PROFILE": "default", "AWS_CONFIG_FILE": filepath.Join(dir, "config"), "AWS_SHARED_CREDENTIALS_FILE": filepath.Join(dir, "credentials"), "AWS_REGION": "eu-west-1", "AWS_DEFAULT_REGION": "eu-west-1"} {
		t.Setenv(k, v)
	}
	t.Run("success", func(t *testing.T) {
		client, err := NewDynamoDBClient(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if client.Options().Region != "eu-west-1" {
			t.Fatalf("region = %q", client.Options().Region)
		}
		creds, err := client.Options().Credentials.Retrieve(context.Background())
		if err != nil || creds.AccessKeyID != "test-key" {
			t.Fatalf("credentials = %#v error = %v", creds, err)
		}
	})
	t.Run("config_failure", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(dir, "config"), []byte("[default\ninvalid"), 0600); err != nil {
			t.Fatal(err)
		}
		client, err := NewDynamoDBClient(context.Background())
		if err == nil || client != nil || !strings.Contains(err.Error(), "failed to load AWS config") {
			t.Fatalf("client = %v error = %v", client, err)
		}
	})
}
