package database

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDynamoDBRuntimeRegionChain(t *testing.T) {
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
			client, err := NewDynamoDBClient(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got := client.Options().Region; got != tc.want {
				t.Fatalf("region = %q, want %q", got, tc.want)
			}
		})
	}
}
