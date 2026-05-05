package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/gin-gonic/gin"
)

// AbuseIPDBClient wraps HTTP access to the AbuseIPDB API with timeouts.
type AbuseIPDBClient struct {
	HTTP    *http.Client
	BaseURL string
	Timeout time.Duration
}

// AbuseIPDBResponse models the subset of fields we care about.
type AbuseIPDBResponse struct {
	Data struct {
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryName          string `json:"countryName"`
		TotalReports         int    `json:"totalReports"`
		IsTor                bool   `json:"isTor"`
		CountryCode          string `json:"countryCode"`
		Usage                string `json:"usageType"`
	} `json:"data"`
}

// NewAbuseIPDBClient constructs a client with sensible defaults.
func NewAbuseIPDBClient() *AbuseIPDBClient {
	return &AbuseIPDBClient{
		HTTP:    &http.Client{Timeout: 5 * time.Second},
		BaseURL: "https://api.abuseipdb.com/api/v2/check",
		Timeout: 5 * time.Second,
	}
}

// CheckIP queries AbuseIPDB for a single IP.
func (abuse *AbuseIPDBClient) CheckIP(c *gin.Context, ip string, ssmClient *ssm.Client, kmsClient *kms.Client, lg *slog.Logger) (*AbuseIPDBResponse, error) {
	ctx, cancel := context.WithTimeout(c, abuse.Timeout)
	defer cancel()
	if abuse.HTTP == nil {
		abuse.HTTP = &http.Client{Timeout: 5 * time.Second}
	}
	if abuse.Timeout <= 0 {
		abuse.Timeout = 5 * time.Second
	}
	if abuse.BaseURL == "" {
		abuse.BaseURL = "https://api.abuseipdb.com/api/v2/check"
	}
	q := url.Values{}
	q.Set("ipAddress", ip)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?%s", abuse.BaseURL, q.Encode()), nil)
	if err != nil {
		lg.Error("failed to create abuseipdb request", "error", err)
		return nil, err
	}
	apiKey, err := GetParam(c, ssmClient, kmsClient, "ipabuse_db", lg)
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := abuse.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("abuseipdb non-2xx: %s", resp.Status)
	}

	var out AbuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}
