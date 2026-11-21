package app

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Acontoso/soar-api/code/models"
	"github.com/Acontoso/soar-api/code/services"
	"github.com/gin-gonic/gin"
)

func TestBlockIPCloudflareCachedAccounts(t *testing.T) {
	oldAccounts, oldLists := services.AccountIDMap, services.ListMap
	services.AccountIDMap, services.ListMap = map[string]string{}, map[string]string{}
	t.Cleanup(func() { services.AccountIDMap, services.ListMap = oldAccounts, oldLists })

	const account = "test-account"
	for _, tt := range []struct {
		name     string
		iocs     []string
		existing map[string]models.SOARTable
		want     []models.CloudflareBlockIPResponsePayload
		wantLogs []string
	}{
		{name: "nil input keeps nil results"},
		{name: "empty input keeps nil results", iocs: []string{}},
		{
			name: "typed cached accounts preserve input order and duplicates",
			iocs: []string{"192.0.2.2", "192.0.2.1", "192.0.2.2"},
			existing: map[string]models.SOARTable{
				"192.0.2.1": {Info: map[string]interface{}{"Accounts": []string{account}}},
				"192.0.2.2": {Info: map[string]interface{}{"Accounts": []string{"other", account}}},
			},
			want: []models.CloudflareBlockIPResponsePayload{
				{IOC: "192.0.2.2", Account: account, Added: true, Action: "Block"},
				{IOC: "192.0.2.1", Account: account, Added: true, Action: "Block"},
				{IOC: "192.0.2.2", Account: account, Added: true, Action: "Block"},
			},
		},
		{
			name: "Dynamo untyped accounts skip non-string entries", iocs: []string{"192.0.2.1"},
			existing: map[string]models.SOARTable{"192.0.2.1": {Info: map[string]interface{}{"Accounts": []interface{}{nil, 42, account}}}},
			want:     []models.CloudflareBlockIPResponsePayload{{IOC: "192.0.2.1", Account: account, Added: true, Action: "Block"}},
		},
		{
			name: "new IOC with missing configuration reports failed add", iocs: []string{"192.0.2.1"},
			want:     []models.CloudflareBlockIPResponsePayload{{IOC: "192.0.2.1", Account: account, Added: false, Action: "None"}},
			wantLogs: []string{"Cloudflare account not found in map"},
		},
		{
			name: "existing IOC does not update membership after failed add", iocs: []string{"192.0.2.1"},
			existing: map[string]models.SOARTable{"192.0.2.1": {Info: map[string]interface{}{"Accounts": []string{"other"}}}},
			want:     []models.CloudflareBlockIPResponsePayload{{IOC: "192.0.2.1", Account: account, Added: false, Action: "None"}},
			wantLogs: []string{"Cloudflare account not found in map"},
		},
		{
			name: "nil cached info is treated as no matching account", iocs: []string{"192.0.2.1"},
			existing: map[string]models.SOARTable{"192.0.2.1": {}},
			want:     []models.CloudflareBlockIPResponsePayload{{IOC: "192.0.2.1", Account: account, Added: false, Action: "None"}},
			wantLogs: []string{"Cloudflare account not found in map"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/cloudflare", nil)
			var logs bytes.Buffer
			lg := slog.New(slog.NewJSONHandler(&logs, nil))
			got, err := (&App{}).blockIPCloudflare(c, tt.iocs, "test", account, tt.existing, lg)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("results = %#v, want %#v", got, tt.want)
			}
			for _, wantLog := range tt.wantLogs {
				if !strings.Contains(logs.String(), wantLog) {
					t.Errorf("logs = %s, missing %q", logs.String(), wantLog)
				}
			}
			if len(tt.wantLogs) == 0 && logs.Len() != 0 {
				t.Errorf("cached/empty path emitted unexpected logs: %s", logs.String())
			}
		})
	}
}
