package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/gin-gonic/gin"
)

type awsTestRoundTripper func(*http.Request) (*http.Response, error)

func (f awsTestRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func awsTestResponse(status int, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: http.Header{"Content-Type": {"application/x-amz-json-1.1"}}, Body: io.NopCloser(bytes.NewReader(data))}, nil
}

func awsTestConfig(transport http.RoundTripper) aws.Config {
	return aws.Config{Region: "ap-southeast-2", Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: &http.Client{Transport: transport}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
}

func awsTestContext() *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	return c
}

func awsTestLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func TestGetParamContracts(t *testing.T) {
	t.Setenv("SSM_PARAMETER_PREFIX", "/soar-api")
	for _, tt := range []struct {
		name      string
		ssmBody   any
		ssmStatus int
		kmsStatus int
		wantErr   bool
		wantKMS   bool
	}{
		{name: "decrypt", ssmBody: map[string]any{"Parameter": map[string]string{"Value": base64.StdEncoding.EncodeToString([]byte("ciphertext"))}}, wantKMS: true},
		{name: "SSM error", ssmStatus: 400, ssmBody: map[string]string{"__type": "ParameterNotFound", "message": "missing"}, wantErr: true},
		{name: "invalid base64", ssmBody: map[string]any{"Parameter": map[string]string{"Value": "%%%"}}, wantErr: true},
		{name: "KMS error", ssmBody: map[string]any{"Parameter": map[string]string{"Value": "Y2lwaGVydGV4dA=="}}, kmsStatus: 400, wantErr: true, wantKMS: true},
		{name: "missing parameter", ssmBody: map[string]any{}, wantErr: true},
		{name: "missing value", ssmBody: map[string]any{"Parameter": map[string]any{}}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			cfg := awsTestConfig(awsTestRoundTripper(func(r *http.Request) (*http.Response, error) {
				var input map[string]any
				if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
					return nil, err
				}
				switch r.Header.Get("X-Amz-Target") {
				case "AmazonSSM.GetParameter":
					calls = append(calls, "SSM")
					if input["Name"] != "/soar-api/api-key" || input["WithDecryption"] != true {
						t.Errorf("SSM input = %#v", input)
					}
					status := tt.ssmStatus
					if status == 0 {
						status = 200
					}
					return awsTestResponse(status, tt.ssmBody)
				case "TrentService.Decrypt":
					calls = append(calls, "KMS")
					if input["CiphertextBlob"] != "Y2lwaGVydGV4dA==" {
						t.Errorf("KMS input = %#v", input)
					}
					if tt.kmsStatus != 0 {
						return awsTestResponse(tt.kmsStatus, map[string]string{"__type": "InvalidCiphertextException", "message": "bad ciphertext"})
					}
					return awsTestResponse(200, map[string]string{"Plaintext": base64.StdEncoding.EncodeToString([]byte("secret"))})
				default:
					return nil, fmt.Errorf("unexpected AWS operation %q", r.Header.Get("X-Amz-Target"))
				}
			}))
			// A missing field must be reported, not panic or reach KMS.
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("GetParam panicked: %v", p)
				}
			}()
			got, err := GetParam(awsTestContext(), ssm.NewFromConfig(cfg), kms.NewFromConfig(cfg), "api-key", awsTestLogger())
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetParam = %q, %v; wantErr %v", got, err, tt.wantErr)
			}
			if !tt.wantErr && got != "secret" {
				t.Errorf("plaintext = %q", got)
			}
			wantCalls := []string{"SSM"}
			if tt.wantKMS {
				wantCalls = append(wantCalls, "KMS")
			}
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Errorf("calls = %v, want %v", calls, wantCalls)
			}
		})
	}
}

func TestGetCognitoTokenContracts(t *testing.T) {
	oldPool, oldLogin := IDENTITY_POOL_ID, IDENTITY_POOL_LOGIN
	IDENTITY_POOL_ID, IDENTITY_POOL_LOGIN = "test-pool", "test-login"
	t.Cleanup(func() { IDENTITY_POOL_ID, IDENTITY_POOL_LOGIN = oldPool, oldLogin })
	for _, tt := range []struct {
		name    string
		status  int
		body    any
		wantErr bool
	}{
		{"token", 200, map[string]string{"Token": "token"}, false},
		{"SDK error", 400, map[string]string{"__type": "NotAuthorizedException", "message": "denied"}, true},
		{"missing token", 200, map[string]any{}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := awsTestConfig(awsTestRoundTripper(func(r *http.Request) (*http.Response, error) {
				if !strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".GetOpenIdTokenForDeveloperIdentity") {
					return nil, fmt.Errorf("unexpected operation %q", r.Header.Get("X-Amz-Target"))
				}
				var input struct {
					IdentityPoolId string
					Logins         map[string]string
				}
				if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
					return nil, err
				}
				if input.IdentityPoolId != "test-pool" || !reflect.DeepEqual(input.Logins, map[string]string{"azuread": "test-login"}) {
					t.Errorf("Cognito request = %#v", input)
				}
				return awsTestResponse(tt.status, tt.body)
			}))
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("GetCognitoToken panicked: %v", p)
				}
			}()
			got, err := GetCognitoToken(awsTestContext(), cognitoidentity.NewFromConfig(cfg), awsTestLogger())
			if (err != nil) != tt.wantErr {
				t.Fatalf("token = %q, error = %v, wantErr %v", got, err, tt.wantErr)
			}
			if !tt.wantErr && got != "token" {
				t.Errorf("token = %q", got)
			}
		})
	}
}

func TestAWSRequestCancellation(t *testing.T) {
	cfg := awsTestConfig(awsTestRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Error("canceled request reached transport")
		return nil, errors.New("unexpected transport call")
	}))
	for _, tt := range []struct {
		name string
		run  func(*gin.Context) error
	}{
		{"SSM", func(c *gin.Context) error {
			_, err := GetParam(c, ssm.NewFromConfig(cfg), kms.NewFromConfig(cfg), "key", awsTestLogger())
			return err
		}},
		{"Cognito", func(c *gin.Context) error {
			_, err := GetCognitoToken(c, cognitoidentity.NewFromConfig(cfg), awsTestLogger())
			return err
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := awsTestContext()
			ctx, cancel := context.WithCancel(c.Request.Context())
			cancel()
			c.Request = c.Request.WithContext(ctx)
			if err := tt.run(c); !errors.Is(err, context.Canceled) {
				t.Errorf("error = %v, want cancellation", err)
			}
		})
	}
}

func TestAWSConstructors(t *testing.T) {
	t.Setenv("AWS_REGION", "ap-southeast-2")
	t.Setenv("AWS_DEFAULT_REGION", "ap-southeast-2")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	dir := t.TempDir()
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "missing-credentials"))
	configFile := filepath.Join(dir, "config")
	t.Setenv("AWS_CONFIG_FILE", configFile)
	for _, tt := range []struct {
		name   string
		create func(context.Context) (string, error)
	}{
		{"SSM", func(ctx context.Context) (string, error) {
			c, err := NewSSMClient(ctx)
			if err != nil {
				return "", err
			}
			return c.Options().Region, nil
		}},
		{"KMS", func(ctx context.Context) (string, error) {
			c, err := NewKMSClient(ctx)
			if err != nil {
				return "", err
			}
			return c.Options().Region, nil
		}},
		{"Cognito", func(ctx context.Context) (string, error) {
			c, err := NewCognitoClient(ctx)
			if err != nil {
				return "", err
			}
			return c.Options().Region, nil
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(configFile, []byte("[default]\nregion=us-east-1\n"), 0600); err != nil {
				t.Fatal(err)
			}
			region, err := tt.create(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if region != "ap-southeast-2" {
				t.Errorf("region = %q", region)
			}
			t.Setenv("AWS_PROFILE", "missing-profile")
			if _, err := tt.create(context.Background()); err == nil {
				t.Error("missing configuration profile was accepted")
			}
		})
	}
}
