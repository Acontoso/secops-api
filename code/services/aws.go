package services

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"time"

	runtimeconfig "github.com/Acontoso/soar-api/code/config"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/gin-gonic/gin"
)

var IDENTITY_POOL_ID string = os.Getenv("IDENTITY_POOL_ID")
var IDENTITY_POOL_LOGIN string = os.Getenv("IDENTITY_POOL_LOGIN")

func NewSSMClient(ctx context.Context) (*ssm.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return ssm.NewFromConfig(cfg), nil
}

func NewCognitoClient(ctx context.Context) (*cognitoidentity.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return cognitoidentity.NewFromConfig(cfg), nil
}

func NewKMSClient(ctx context.Context) (*kms.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return kms.NewFromConfig(cfg), nil
}

type parameterGetter interface {
	GetParameter(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

type ciphertextDecrypter interface {
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

func GetParam(c *gin.Context, ssmClient *ssm.Client, kmsClient *kms.Client, param string, lg *slog.Logger) (string, error) {
	return getParam(c, ssmClient, kmsClient, param, lg)
}

func getParam(c *gin.Context, ssmClient parameterGetter, kmsClient ciphertextDecrypter, param string, lg *slog.Logger) (string, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	parameter, err := runtimeconfig.SSMParameterName(param)
	if err != nil {
		return "", err
	}
	withDecryption := true
	input := &ssm.GetParameterInput{
		Name:           &parameter,
		WithDecryption: &withDecryption, // true if SecureString needs decryption
	}
	result, err := ssmClient.GetParameter(ctx, input)
	if err != nil {
		lg.Error("failed to get ssm parameter", "parameter", parameter, "error", err)
		return "", err
	}
	if result == nil || result.Parameter == nil || result.Parameter.Value == nil {
		err := fmt.Errorf("ssm parameter %q returned no value", parameter)
		lg.Error("failed to get ssm parameter", "parameter", parameter, "error", err)
		return "", err
	}
	// Dereference the pointer to get the actual string value
	stringData := *result.Parameter.Value
	decodedBytes, err := base64.StdEncoding.DecodeString(stringData)
	if err != nil {
		lg.Error("failed to decode base64 data", "parameter", parameter, "error", err)
		return "", err
	}
	// Decrypt the data using KMS
	decryptInput := &kms.DecryptInput{
		CiphertextBlob: decodedBytes,
	}
	decryptResult, err := kmsClient.Decrypt(ctx, decryptInput)
	if err != nil {
		lg.Error("failed to decrypt kms data", "parameter", parameter, "error", err)
		return "", err
	}
	// Convert the decrypted binary data back to string
	stringData = string(decryptResult.Plaintext)
	return stringData, nil
}

func GetCognitoToken(c *gin.Context, cognitoClient *cognitoidentity.Client, lg *slog.Logger) (string, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	logins := map[string]string{
		"azuread": IDENTITY_POOL_LOGIN,
	}
	resp, err := cognitoClient.GetOpenIdTokenForDeveloperIdentity(ctx, &cognitoidentity.GetOpenIdTokenForDeveloperIdentityInput{
		IdentityPoolId: &IDENTITY_POOL_ID,
		Logins:         logins,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	if resp == nil || resp.Token == nil {
		return "", fmt.Errorf("cognito returned no token")
	}
	return *resp.Token, nil
}
