package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/gin-gonic/gin"
)

func TestAWSRuntimeRegionChain(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "dummy")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "dummy")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "no-credentials"))
	file := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(file, []byte("[default]\nregion = eu-central-1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", file)
	for _, tc := range []struct{ name, region, fallback, want string }{
		{"AWS_REGION wins", "us-east-1", "us-west-2", "us-east-1"},
		{"AWS_DEFAULT_REGION fallback", "", "us-west-2", "us-west-2"},
		{"shared config fallback", "", "", "eu-central-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AWS_REGION", tc.region)
			t.Setenv("AWS_DEFAULT_REGION", tc.fallback)
			ctx := context.Background()
			ssmClient, err := NewSSMClient(ctx)
			if err != nil {
				t.Fatal(err)
			}
			kmsClient, err := NewKMSClient(ctx)
			if err != nil {
				t.Fatal(err)
			}
			cognitoClient, err := NewCognitoClient(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for name, got := range map[string]string{"SSM": ssmClient.Options().Region, "KMS": kmsClient.Options().Region, "Cognito": cognitoClient.Options().Region} {
				if got != tc.want {
					t.Errorf("%s region = %q, want %q", name, got, tc.want)
				}
			}
		})
	}
}

type configParameterGetter func(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)

func (f configParameterGetter) GetParameter(ctx context.Context, input *ssm.GetParameterInput, opts ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	return f(ctx, input, opts...)
}

type configCiphertextDecrypter func(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)

func (f configCiphertextDecrypter) Decrypt(ctx context.Context, input *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	return f(ctx, input, opts...)
}

func TestNamespacedLayeredDecryptionContract(t *testing.T) {
	for _, prefix := range []string{"/soar-api/dev", "/soar-api/prod"} {
		t.Run(prefix, func(t *testing.T) {
			t.Setenv("SSM_PARAMETER_PREFIX", prefix)
			t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "dummy-function")
			ciphertext := []byte{0, 1, 2, 127, 255}
			ssmCalled, kmsCalled := false, false
			getter := configParameterGetter(func(_ context.Context, input *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
				ssmCalled = true
				if aws.ToString(input.Name) != prefix+"/api-key" || !aws.ToBool(input.WithDecryption) {
					t.Fatalf("unexpected SSM input: %+v", input)
				}
				return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: aws.String(base64.StdEncoding.EncodeToString(ciphertext))}}, nil
			})
			decrypter := configCiphertextDecrypter(func(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
				kmsCalled = true
				if !ssmCalled || !bytes.Equal(input.CiphertextBlob, ciphertext) || input.KeyId != nil || len(input.EncryptionContext) != 0 {
					t.Fatalf("application KMS contract changed: %+v", input)
				}
				return &kms.DecryptOutput{Plaintext: []byte("decrypted-secret")}, nil
			})
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			got, err := getParam(c, getter, decrypter, "api-key", slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil || got != "decrypted-secret" || !kmsCalled {
				t.Fatalf("got %q, %v; KMS called %v", got, err, kmsCalled)
			}
		})
	}
}

func TestManagedNamespaceFailsBeforeAWS(t *testing.T) {
	t.Setenv("SSM_PARAMETER_PREFIX", "")
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "dummy-function")
	getter := configParameterGetter(func(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
		t.Fatal("missing namespace reached SSM")
		return nil, errors.New("unexpected call")
	})
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := getParam(c, getter, nil, "key", slog.Default()); err == nil {
		t.Fatal("missing managed namespace was accepted")
	}
}
