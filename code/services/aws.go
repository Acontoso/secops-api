package services

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/gin-gonic/gin"
)

// var IDENTITY_POOL_ID = os.Getenv("IDENTITY_POOL_LOGIN")
var IDENTITY_POOL_ID string = os.Getenv("IDENTITY_POOL_ID")
var IDENTITY_POOL_LOGIN string = os.Getenv("IDENTITY_POOL_LOGIN")

func NewSSMClient(ctx context.Context) (*ssm.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("ap-southeast-2"))
	if err != nil {
		return nil, err
	}
	return ssm.NewFromConfig(cfg), nil
}

func NewCognitoClient(ctx context.Context) (*cognitoidentity.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("ap-southeast-2"))
	if err != nil {
		return nil, err
	}
	return cognitoidentity.NewFromConfig(cfg), nil
}

func NewKMSClient(ctx context.Context) (*kms.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("ap-southeast-2"))
	if err != nil {
		return nil, err
	}
	return kms.NewFromConfig(cfg), nil
}

func GetParam(c *gin.Context, ssm_client *ssm.Client, kms_client *kms.Client, param string, lg *slog.Logger) (string, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	parameter := fmt.Sprintf("/soar-api/%s", param)
	withDecryption := true
	input := &ssm.GetParameterInput{
		Name:           &parameter,
		WithDecryption: &withDecryption, // true if SecureString needs decryption
	}
	result, err := ssm_client.GetParameter(ctx, input)
	if err != nil {
		lg.Error("failed to get ssm parameter", "parameter", parameter, "error", err)
		return "", err
	}
	// Dereference the pointer to get the actual string value
	stringdata := *result.Parameter.Value
	decodedBytes, err := base64.StdEncoding.DecodeString(stringdata)
	if err != nil {
		lg.Error("failed to decode base64 data", "parameter", parameter, "error", err)
		return "", err
	}
	// Decrypt the data using KMS
	decryptInput := &kms.DecryptInput{
		CiphertextBlob: decodedBytes,
	}
	decryptResult, err := kms_client.Decrypt(ctx, decryptInput)
	if err != nil {
		lg.Error("failed to decrypt kms data", "parameter", parameter, "error", err)
		return "", err
	}
	// Convert the decrypted binary data back to string
	stringdata = string(decryptResult.Plaintext)
	return stringdata, nil
}

func GetCognitoToken(c *gin.Context, cognito_client *cognitoidentity.Client, lg *slog.Logger) (string, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	logins := map[string]string{
		"azuread": IDENTITY_POOL_LOGIN,
	}
	resp, err := cognito_client.GetOpenIdTokenForDeveloperIdentity(ctx, &cognitoidentity.GetOpenIdTokenForDeveloperIdentityInput{
		IdentityPoolId: &IDENTITY_POOL_ID,
		Logins:         logins,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	return *resp.Token, nil
}
