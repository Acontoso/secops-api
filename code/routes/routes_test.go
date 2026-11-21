package routes

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	appcontainer "github.com/Acontoso/soar-api/code/app"
	"github.com/gin-gonic/gin"
)

func TestProtectedRouteContracts(t *testing.T) {
	for name, value := range map[string]string{
		"AWS_REGION": "us-east-1", "AWS_CONFIG_FILE": os.DevNull, "AWS_SHARED_CREDENTIALS_FILE": os.DevNull,
		"AWS_PROFILE": "", "AWS_DEFAULT_PROFILE": "", "AWS_EC2_METADATA_DISABLED": "true",
		"COGNITO_USER_POOL_ID": "us-east-1_test", "COGNITO_CLIENT_ID": "client", "COGNITO_REQUIRED_SCOPE": "custom/read",
	} {
		t.Setenv(name, value)
	}
	r := gin.New()
	// All integration clients intentionally remain nil. Without authentication's
	// abort, malformed JSON would reach a handler and return 400 instead of 401.
	SetupProtectedRoutes(&appcontainer.App{Router: r})
	paths := []string{
		"/api/enrich/ipabusedb", "/api/enrich/ipabusedb/manual", "/api/enrich/ipabusedb/create",
		"/api/enrich/anomali", "/api/enrich/recordedfuture", "/api/soar/sse/zscaler",
		"/api/soar/azuread/ca", "/api/soar/datp/blockioc", "/api/soar/waf/blockip",
	}
	registered := make(map[string]string)
	for _, route := range r.Routes() {
		if route.Method != http.MethodPost {
			t.Errorf("unexpected method: %+v", route)
		}
		registered[route.Path] = route.Handler
	}
	if len(registered) != len(paths) {
		t.Fatalf("registered %d routes, want %d", len(registered), len(paths))
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			if registered[path] == "" {
				t.Fatalf("route not registered")
			}
			for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodOptions, http.MethodHead} {
				req := httptest.NewRequest(method, path, strings.NewReader(`{`))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				want := http.StatusNotFound // HandleMethodNotAllowed is false by default.
				if method == http.MethodPost {
					want = http.StatusUnauthorized
				}
				if w.Code != want {
					t.Fatalf("%s: got %d want %d: %s", method, w.Code, want, w.Body.String())
				}
				if method == http.MethodPost && (w.Body.String() != `{"error":"Unauthorized"}` || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json")) {
					t.Fatalf("auth response changed: %s", w.Body.String())
				}
			}
		})
	}
	for _, path := range []string{"/missing", "/api/enrich", "/api/soar", "/api/enrich/IPABUSEDB", "/api/soar/waf/blockip/extra"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("unknown %s = %d", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, paths[0]+"/", nil))
	if w.Code != http.StatusTemporaryRedirect || w.Header().Get("Location") != paths[0] {
		t.Fatalf("trailing slash redirect: %d %v", w.Code, w.Header())
	}
}
