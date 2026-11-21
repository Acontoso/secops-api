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

// AnomaliClient wraps HTTP access to the Anomali API with timeouts.
type AnomaliClient struct {
	HTTP    *http.Client
	BaseURL string
	Timeout time.Duration
}

// NewAnomaliClient constructs a client with sensible defaults.
func NewAnomaliClient() *AnomaliClient {
	return &AnomaliClient{
		HTTP:    &http.Client{Timeout: 5 * time.Second},
		BaseURL: "https://api.threatstream.com/api/v1/inteldetails/confidence_trend/?type=confidence",
		Timeout: 5 * time.Second,
	}
}

type AnomaliResponse struct {
	Confidence int `json:"average_confidence"`
}

// CheckIOC queries Anomali for the confidence score of a single IOC.
func (anomali *AnomaliClient) CheckIOC(c *gin.Context, ioc string, ssmClient *ssm.Client, kmsClient *kms.Client, lg *slog.Logger) (int, error) {
	if anomali.HTTP == nil {
		anomali.HTTP = &http.Client{Timeout: 5 * time.Second}
	}
	if anomali.Timeout <= 0 {
		anomali.Timeout = 5 * time.Second
	}
	if anomali.BaseURL == "" {
		anomali.BaseURL = "https://api.threatstream.com/api/v1/inteldetails/confidence_trend/"
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), anomali.Timeout)
	defer cancel()
	// Build URL with query parameters
	parsedURL, err := url.Parse(anomali.BaseURL)
	if err != nil {
		lg.Error("failed to parse base url", "error", err)
		return 0, err
	}
	q := parsedURL.Query()
	q.Set("type", "confidence")
	q.Set("value", ioc)
	parsedURL.RawQuery = q.Encode()
	finalURL := parsedURL.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, finalURL, nil)
	if err != nil {
		lg.Error("failed to create anomali request", "error", err)
		return 0, err
	}
	apiKey, err := GetParam(c, ssmClient, kmsClient, "anomali_api", lg)
	if err != nil {
		return 0, err
	}
	anomaliUser, err := GetParam(c, ssmClient, kmsClient, "anomali_user", lg)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("apikey %s:%s", anomaliUser, apiKey))
	resp, err := anomali.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		lg.Error("anomali non-2xx:", "status", resp.Status)
		return 0, fmt.Errorf("anomali non-2xx: %s", resp.Status)
	}

	var out AnomaliResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}
	return out.Confidence, nil
}
