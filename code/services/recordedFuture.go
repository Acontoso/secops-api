package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/Acontoso/soar-api/code/models"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/gin-gonic/gin"
)

// FutureClient wraps HTTP access to the Recorded Future API with timeouts.
type FutureClient struct {
	HTTP    *http.Client
	BaseURL string
	Timeout time.Duration
}

// NewFutureClient constructs a client with sensible defaults.
func NewFutureClient() *FutureClient {
	return &FutureClient{
		HTTP:    &http.Client{Timeout: 15 * time.Second},
		Timeout: 15 * time.Second,
	}
}

// enrichmentPayload builds the category-specific body. An unsupported IOC type
// produces a nil body, matching the original request behaviour.
func enrichmentPayload(ioc, iocType string) ([]byte, error) {
	var payload models.RecordFutureAPICallSOAR
	switch iocType {
	case "IPv4", "IPv6":
		payload.IP = []string{ioc}
	case "Domain":
		payload.Domain = []string{ioc}
	case "SHA1", "SHA256", "MD5":
		payload.Hash = []string{ioc}
	default:
		return nil, nil
	}
	return json.Marshal(payload)
}

// GetRecordedFutureEnrichment queries Recorded Future for a single IOC.
func (future *FutureClient) GetRecordedFutureEnrichment(c *gin.Context, ioc string, ssmClient *ssm.Client, kmsClient *kms.Client, lg *slog.Logger) (int, error) {
	if future.HTTP == nil {
		future.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if future.Timeout <= 0 {
		future.Timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), future.Timeout)
	defer cancel()
	baseURL := future.BaseURL
	if baseURL == "" {
		baseURL = "https://api.recordedfuture.com/soar/v3/enrichment"
	}
	// Build URL with query parameters
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		lg.Error("failed to parse base url", "error", err)
		return 0, err
	}
	finalURL := parsedURL.String()
	payloadBytes, err := enrichmentPayload(ioc, models.IOCClassifier(ioc))
	if err != nil {
		lg.Error("failed to marshal payload", "error", err)
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, finalURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		lg.Error("Failed to create RecordedFuture API request", "error", err)
		return 0, err
	}
	apiKey, err := GetParam(c, ssmClient, kmsClient, "recorded_future_api", lg)
	if err != nil {
		lg.Error("Failed to retrieve Recorded Future API key", "error", err)
		return 0, err
	}
	req.Header.Set("X-RFToken", fmt.Sprintf("%s", apiKey))
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/json")
	resp, err := future.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		lg.Error("recorded future non-2xx:", "status", resp.Status)
		return 0, fmt.Errorf("recorded future non-2xx: %s", resp.Status)
	}

	var out models.RecordedFutureResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}

	// Access the risk score from the first result
	if len(out.Data.Results) > 0 {
		return out.Data.Results[0].Risk.Score, nil
	}
	return 0, fmt.Errorf("no results in Recorded Future response")
}
