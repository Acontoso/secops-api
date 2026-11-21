package config

import (
	"context"
	"path/filepath"
	"testing"
)

func isolateEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "COGNITO_USER_POOL_ID", "COGNITO_CLIENT_ID", "COGNITO_REQUIRED_SCOPE", "SSM_PARAMETER_PREFIX", "AWS_LAMBDA_FUNCTION_NAME", "AWS_EXECUTION_ENV", "ECS_CONTAINER_METADATA_URI", "ECS_CONTAINER_METADATA_URI_V4"} {
		t.Setenv(name, "")
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "no-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "no-credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "dummy")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "dummy")
}

func TestLoadCognito(t *testing.T) {
	for _, tc := range []struct {
		name, region, fallback, pool, client, scope, wantIssuer, wantScope string
		wantErr                                                            bool
	}{
		{name: "missing configuration", wantErr: true},
		{name: "missing region", pool: "us-east-1_test", client: "client", wantErr: true},
		{name: "missing pool", region: "us-east-1", client: "client", wantErr: true},
		{name: "missing client", region: "us-east-1", pool: "us-east-1_test", wantErr: true},
		{name: "pool region mismatch", region: "us-west-2", pool: "us-east-1_test", client: "client", wantErr: true},
		{name: "invalid pool", region: "us-east-1", pool: "us-east-1_test/other", client: "client", wantErr: true},
		{name: "default scope", region: "us-east-1", pool: "us-east-1_test", client: "client", wantIssuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test", wantScope: DefaultRequiredScope},
		{name: "fallback region and custom scope", fallback: "eu-west-1", pool: "eu-west-1_test", client: "client", scope: "custom/read", wantIssuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_test", wantScope: "custom/read"},
		{name: "region precedence", region: "us-east-1", fallback: "eu-west-1", pool: "us-east-1_test", client: "client", wantIssuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test", wantScope: DefaultRequiredScope},
		{name: "multiple required scopes", region: "us-east-1", pool: "us-east-1_test", client: "client", scope: "one two", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateEnvironment(t)
			t.Setenv("AWS_REGION", tc.region)
			t.Setenv("AWS_DEFAULT_REGION", tc.fallback)
			t.Setenv("COGNITO_USER_POOL_ID", tc.pool)
			t.Setenv("COGNITO_CLIENT_ID", tc.client)
			t.Setenv("COGNITO_REQUIRED_SCOPE", tc.scope)
			cfg, err := LoadCognito(context.Background())
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected configuration error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Issuer != tc.wantIssuer || cfg.ClientID != tc.client || cfg.RequiredScope != tc.wantScope {
				t.Fatalf("unexpected config: %+v", cfg)
			}
		})
	}
}

func TestSSMParameterName(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, managed, param, want string
		wantErr                            bool
	}{
		{name: "local compatibility", param: "vendor/key", want: "/soar-api/vendor/key"},
		{name: "dev", prefix: "/soar-api/dev", param: "key", want: "/soar-api/dev/key"},
		{name: "prod", prefix: "/soar-api/prod/", param: "key", want: "/soar-api/prod/key"},
		{name: "managed requires namespace", managed: "AWS_LAMBDA_FUNCTION_NAME", param: "key", wantErr: true},
		{name: "managed execution env", managed: "AWS_EXECUTION_ENV", param: "key", wantErr: true},
		{name: "managed ECS", managed: "ECS_CONTAINER_METADATA_URI_V4", param: "key", wantErr: true},
		{name: "managed explicit namespace", managed: "AWS_LAMBDA_FUNCTION_NAME", prefix: "/soar-api/dev", param: "key", want: "/soar-api/dev/key"},
		{name: "relative prefix", prefix: "soar-api/dev", param: "key", wantErr: true},
		{name: "root prefix", prefix: "/", param: "key", wantErr: true},
		{name: "prefix traversal", prefix: "/soar-api/../prod", param: "key", wantErr: true},
		{name: "param traversal", prefix: "/soar-api/dev", param: "../prod/key", wantErr: true},
		{name: "absolute param", param: "/key", wantErr: true},
		{name: "empty param", wantErr: true},
		{name: "double slash", prefix: "/soar-api//dev", param: "key", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateEnvironment(t)
			t.Setenv("SSM_PARAMETER_PREFIX", tc.prefix)
			if tc.managed != "" {
				t.Setenv(tc.managed, "test")
			}
			got, err := SSMParameterName(tc.param)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected namespace error")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}
