package middleware

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Acontoso/soar-api/code/config"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func testJWKSet(t *testing.T, key *rsa.PrivateKey) keyfunc.Keyfunc {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"keys": []any{map[string]string{
		"kty": "RSA", "kid": "local-test", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyfunc.NewJWKSetJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func testAccessClaims(cfg config.Cognito) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": cfg.Issuer, "exp": time.Now().Add(time.Hour).Unix(),
		"sub": "caller-not-client-id", "client_id": cfg.ClientID,
		"token_use": "access", "scope": "other/read " + cfg.RequiredScope,
	}
}

func signAccessToken(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "local-test"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func requestProtected(middleware gin.HandlerFunc, header string) *httptest.ResponseRecorder {
	r := gin.New()
	r.Use(middleware)
	r.GET("/protected", func(c *gin.Context) { c.String(http.StatusOK, c.GetString("username")) })
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", header)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestCognitoAccessTokenValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := testJWKSet(t, key)
	cfg := config.Cognito{Issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test", ClientID: "configured-client", RequiredScope: config.DefaultRequiredScope}
	for _, tc := range []struct {
		name   string
		mutate func(jwt.MapClaims)
		want   int
	}{
		{name: "access token with distinct subject", want: http.StatusOK},
		{name: "ID token", mutate: func(c jwt.MapClaims) { c["token_use"] = "id" }, want: http.StatusUnauthorized},
		{name: "missing token use", mutate: func(c jwt.MapClaims) { delete(c, "token_use") }, want: http.StatusUnauthorized},
		{name: "wrong client even if subject matches", mutate: func(c jwt.MapClaims) { c["client_id"] = "other"; c["sub"] = cfg.ClientID }, want: http.StatusUnauthorized},
		{name: "missing client", mutate: func(c jwt.MapClaims) { delete(c, "client_id") }, want: http.StatusUnauthorized},
		{name: "wrong issuer", mutate: func(c jwt.MapClaims) { c["iss"] = "https://other.invalid" }, want: http.StatusUnauthorized},
		{name: "missing issuer", mutate: func(c jwt.MapClaims) { delete(c, "iss") }, want: http.StatusUnauthorized},
		{name: "expired", mutate: func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, want: http.StatusUnauthorized},
		{name: "missing expiry", mutate: func(c jwt.MapClaims) { delete(c, "exp") }, want: http.StatusUnauthorized},
		{name: "invalid expiry", mutate: func(c jwt.MapClaims) { c["exp"] = "invalid" }, want: http.StatusUnauthorized},
		{name: "not yet valid", mutate: func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }, want: http.StatusUnauthorized},
		{name: "missing scope", mutate: func(c jwt.MapClaims) { delete(c, "scope") }, want: http.StatusUnauthorized},
		{name: "scope substring is insufficient", mutate: func(c jwt.MapClaims) { c["scope"] = cfg.RequiredScope + ".extra" }, want: http.StatusUnauthorized},
		{name: "non string scope", mutate: func(c jwt.MapClaims) { c["scope"] = []string{cfg.RequiredScope} }, want: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := testAccessClaims(cfg)
			if tc.mutate != nil {
				tc.mutate(claims)
			}
			mw := cognitoAuthMiddleware(cfg, func(issuer string) (keyfunc.Keyfunc, error) {
				if issuer != cfg.Issuer {
					t.Fatalf("unexpected issuer: %s", issuer)
				}
				return keys, nil
			})
			w := requestProtected(mw, "Bearer "+signAccessToken(t, key, claims))
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
			if tc.want == http.StatusOK && w.Body.String() != "caller-not-client-id" {
				t.Fatalf("wrong caller: %s", w.Body.String())
			}
		})
	}

	mw := cognitoAuthMiddleware(cfg, func(string) (keyfunc.Keyfunc, error) { return keys, nil })
	valid := signAccessToken(t, key, testAccessClaims(cfg))
	for _, header := range []string{"", "Bearer", "Basic abc", "prefix Bearer abc", "Bearer one two", "Bearer invalid.jwt.value", " Bearer " + valid, "Bearer\t" + valid, "Bearer " + valid + " ", "Bearer " + valid + "\r\n"} {
		if w := requestProtected(mw, header); w.Code != http.StatusUnauthorized {
			t.Fatalf("accepted malformed header %q", header)
		}
	}
	hmac := jwt.NewWithClaims(jwt.SigningMethodHS256, testAccessClaims(cfg))
	hmac.Header["kid"] = "local-test"
	raw, err := hmac.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if w := requestProtected(mw, "Bearer "+raw); w.Code != http.StatusUnauthorized {
		t.Fatal("accepted non-RS256 token")
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if w := requestProtected(mw, "Bearer "+signAccessToken(t, otherKey, testAccessClaims(cfg))); w.Code != http.StatusUnauthorized {
		t.Fatal("accepted invalid signature")
	}
}

func TestCognitoJWKSFailureRetriesAndCaches(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := testJWKSet(t, key)
	cfg := config.Cognito{Issuer: "https://issuer.invalid", ClientID: "client", RequiredScope: "custom/read"}
	calls := 0
	mw := cognitoAuthMiddleware(cfg, func(string) (keyfunc.Keyfunc, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("JWKS unavailable")
		}
		return keys, nil
	})
	header := "Bearer " + signAccessToken(t, key, testAccessClaims(cfg))
	for i, want := range []int{http.StatusUnauthorized, http.StatusOK, http.StatusOK} {
		if w := requestProtected(mw, header); w.Code != want {
			t.Fatalf("request %d: got %d want %d", i, w.Code, want)
		}
	}
	if calls != 2 {
		t.Fatalf("JWKS loaded %d times, want 2", calls)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestJWKSLoaderRefreshLifecycle(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	set, err := testJWKSet(t, key).Storage().Marshal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var calls atomic.Int32
		client := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			if r.Method != http.MethodGet || r.URL.String() != "https://issuer.invalid/.well-known/jwks.json" {
				t.Errorf("unexpected JWKS request: %s %s", r.Method, r.URL)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
		})}
		keys, err := loadJWKS(ctx, "https://issuer.invalid", client)
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatalf("initial calls = %d", calls.Load())
		}
		if _, err := jwt.Parse(signAccessToken(t, key, testAccessClaims(config.Cognito{Issuer: "https://issuer.invalid"})), keys.Keyfunc); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Hour)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatalf("refresh calls = %d", calls.Load())
		}
		cancel()
		synctest.Wait()
		time.Sleep(2 * time.Hour)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatalf("refresh continued after cancellation: %d", calls.Load())
		}
	})
}

func TestJWKSLoaderErrorsAreNotFatal(t *testing.T) {
	// A malformed URL is a constructor error. Initial HTTP outages are not:
	// keyfunc intentionally keeps an empty, refreshing set in that case.
	if _, err := getJWKS("%"); err == nil {
		t.Fatal("expected malformed issuer error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	client := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("offline outage")
	})}
	keys, err := loadJWKS(ctx, "https://issuer.invalid", client)
	if err != nil || keys == nil || calls != 1 {
		t.Fatalf("outage constructor = %v, %v; calls=%d", keys, err, calls)
	}
}

func TestCognitoAbortAndLoggerPropagation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := testJWKSet(t, key)
	cfg := config.Cognito{Issuer: "https://issuer.invalid", ClientID: "client", RequiredScope: "custom/read"}
	for _, subject := range []string{"caller-not-client-id", ""} {
		t.Run("subject="+subject, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil)).With("request_id", "upstream-id")
			loaderCalls := 0
			r := gin.New()
			var captured *gin.Context
			r.Use(func(c *gin.Context) { captured = c; c.Set("logger", logger); c.Next() })
			r.Use(cognitoAuthMiddleware(cfg, func(string) (keyfunc.Keyfunc, error) { loaderCalls++; return keys, nil }))
			handlers := 0
			r.GET("/protected", func(c *gin.Context) {
				handlers++
				if c.GetString("username") != subject {
					t.Errorf("username = %q", c.GetString("username"))
				}
				GetLogger(c).Info("handler reached")
				c.Status(http.StatusNoContent)
			})
			for _, valid := range []bool{false, true} {
				req := httptest.NewRequest(http.MethodGet, "/protected", nil)
				if valid {
					claims := testAccessClaims(cfg)
					if subject == "" {
						delete(claims, "sub")
					} else {
						claims["sub"] = subject
					}
					req.Header.Set("Authorization", "bEaReR  "+signAccessToken(t, key, claims))
				}
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				if !valid {
					if w.Code != http.StatusUnauthorized || w.Body.String() != `{"error":"Unauthorized"}` || !captured.IsAborted() || handlers != 0 || loaderCalls != 0 {
						t.Fatalf("failed authentication did not abort before loader/handler: %d %s", w.Code, w.Body.String())
					}
				} else if w.Code != http.StatusNoContent || captured.IsAborted() || handlers != 1 {
					t.Fatalf("valid request: %d", w.Code)
				}
			}
			var entry map[string]any
			if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
				t.Fatal(err)
			}
			if entry["request_id"] != "upstream-id" || entry["user_id"] != subject {
				t.Fatalf("logger fields lost: %v", entry)
			}
		})
	}
}

func TestCognitoConcurrentRequestsInitializeOnce(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := testJWKSet(t, key)
	cfg := config.Cognito{Issuer: "https://issuer.invalid", ClientID: "client", RequiredScope: "custom/read"}
	var calls atomic.Int32
	mw := cognitoAuthMiddleware(cfg, func(string) (keyfunc.Keyfunc, error) { calls.Add(1); return keys, nil })
	r := gin.New()
	r.Use(mw)
	r.GET("/protected", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	header := "Bearer " + signAccessToken(t, key, testAccessClaims(cfg))
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", header)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				t.Errorf("status = %d", w.Code)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("initializations = %d", calls.Load())
	}
}

func TestCognitoConfiguredConstructor(t *testing.T) {
	for name, value := range map[string]string{
		"AWS_REGION": "us-east-1", "AWS_CONFIG_FILE": os.DevNull, "AWS_SHARED_CREDENTIALS_FILE": os.DevNull,
		"AWS_PROFILE": "", "AWS_DEFAULT_PROFILE": "", "AWS_EC2_METADATA_DISABLED": "true",
		"COGNITO_USER_POOL_ID": "us-east-1_test", "COGNITO_CLIENT_ID": "client", "COGNITO_REQUIRED_SCOPE": "custom/read",
	} {
		t.Setenv(name, value)
	}
	if w := requestProtected(CognitoAuthMiddleware(), "Bearer\tinvalid"); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Unauthorized") {
		t.Fatalf("bad header: %d %s", w.Code, w.Body.String())
	}
}

func TestCognitoMissingConfigurationFailsClosed(t *testing.T) {
	t.Setenv("COGNITO_USER_POOL_ID", "")
	t.Setenv("COGNITO_CLIENT_ID", "")
	if w := requestProtected(CognitoAuthMiddleware(), "Bearer anything"); w.Code != http.StatusUnauthorized {
		t.Fatal("missing config did not fail closed")
	}
}
