// Package config contains the environment-specific runtime contract.
package config

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

const DefaultRequiredScope = "soar-api/admin.readwrite.all"

type Cognito struct {
	Issuer        string
	ClientID      string
	RequiredScope string
}

var poolPattern = regexp.MustCompile(`^[a-z0-9-]+_[A-Za-z0-9]+$`)

// LoadCognito uses the same region resolution chain as the AWS service clients.
func LoadCognito(ctx context.Context) (Cognito, error) {
	pool := strings.TrimSpace(os.Getenv("COGNITO_USER_POOL_ID"))
	client := strings.TrimSpace(os.Getenv("COGNITO_CLIENT_ID"))
	if !poolPattern.MatchString(pool) || client == "" {
		return Cognito{}, fmt.Errorf("COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID are required")
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return Cognito{}, fmt.Errorf("load Cognito region: %w", err)
	}
	if cfg.Region == "" || !strings.HasPrefix(pool, cfg.Region+"_") {
		return Cognito{}, fmt.Errorf("Cognito user pool must match the configured AWS region")
	}
	scope := strings.TrimSpace(os.Getenv("COGNITO_REQUIRED_SCOPE"))
	if scope == "" {
		scope = DefaultRequiredScope
	}
	if len(strings.Fields(scope)) != 1 {
		return Cognito{}, fmt.Errorf("COGNITO_REQUIRED_SCOPE must be a single scope")
	}
	suffix := "amazonaws.com"
	if strings.HasPrefix(cfg.Region, "cn-") {
		suffix = "amazonaws.com.cn"
	}
	return Cognito{
		Issuer:   fmt.Sprintf("https://cognito-idp.%s.%s/%s", cfg.Region, suffix, pool),
		ClientID: client, RequiredScope: scope,
	}, nil
}

// SSMParameterName requires an explicit namespace in AWS-managed runtimes.
// Local use retains the historical /soar-api default. Parameter names are
// relative to the namespace; traversal and ambiguous separators are rejected.
func SSMParameterName(param string) (string, error) {
	prefix := strings.TrimSpace(os.Getenv("SSM_PARAMETER_PREFIX"))
	if prefix == "" {
		for _, name := range []string{"AWS_LAMBDA_FUNCTION_NAME", "AWS_EXECUTION_ENV", "ECS_CONTAINER_METADATA_URI", "ECS_CONTAINER_METADATA_URI_V4"} {
			if os.Getenv(name) != "" {
				return "", fmt.Errorf("SSM_PARAMETER_PREFIX is required in managed environments")
			}
		}
		prefix = "/soar-api"
	}
	prefix = strings.TrimRight(prefix, "/")
	if !strings.HasPrefix(prefix, "/") || !validPath(strings.TrimPrefix(prefix, "/")) || !validPath(param) {
		return "", fmt.Errorf("invalid SSM namespace or parameter name")
	}
	return prefix + "/" + param, nil
}

func validPath(value string) bool {
	if value == "" {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, " \t\r\n\\") {
			return false
		}
	}
	return true
}
