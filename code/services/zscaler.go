package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Acontoso/soar-api/code/models"

	"github.com/gin-gonic/gin"
)

var ZSCALER_SOAR_FQDN_LIST string = "9999988"
var ZSCALER_SOAR_IP_LIST string = "9999999"
var SCOPE string = "api://id/.default"

// AbuseIPDBClient wraps HTTP access to the AbuseIPDB API with timeouts.
type ZscalerClient struct {
	HTTP    *http.Client
	BaseURL string
	Timeout time.Duration
}

// NewZscalerClient constructs a client with sensible defaults.
func NewZscalerClient() *ZscalerClient {
	return &ZscalerClient{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		BaseURL: "https://zsapi.zscalerdc.net/api/v1/ipDestinationGroups",
		Timeout: 30 * time.Second,
	}
}

type ZscalerResponse struct {
	Confidence int `json:"average_confidence"`
}

// BlockIOC queries Zscaler for a single IOC.
func (zscaler *ZscalerClient) BlockIOC(c *gin.Context, ioc string, accessToken string, lg *slog.Logger) (bool, error) {
	ctx, cancel := context.WithTimeout(c, zscaler.Timeout)
	defer cancel()
	if zscaler.HTTP == nil {
		zscaler.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if zscaler.Timeout <= 0 {
		zscaler.Timeout = 30 * time.Second
	}
	if zscaler.BaseURL == "" {
		zscaler.BaseURL = "https://zsapi.zscalerdc.net/api/v1/ipDestinationGroups"
	}

	var reqURL string
	var body models.ZscalerAddPayload
	iocType := models.IOCClassifier(ioc)
	if iocType == "Domain" {
		list_id := ZSCALER_SOAR_FQDN_LIST
		reqURL = fmt.Sprintf("https://zsapi.zscalerdc.net/api/v1/ipDestinationGroups/%s", list_id)
		body = models.ZscalerAddPayload{
			Addresses: []string{ioc},
			Type:      "DSTN_FQDN",
			Name:      "SOAR Malicious Domain List",
		}
	}
	if iocType == "IPv4" || iocType == "IPv6" {
		list_id := ZSCALER_SOAR_IP_LIST
		reqURL = fmt.Sprintf("https://zsapi.zscalerdc.net/api/v1/ipDestinationGroups/%s", list_id)
		body = models.ZscalerAddPayload{
			Addresses: []string{ioc},
			Type:      "DSTN_IP",
			Name:      "SOAR Malicious IP Address List",
		}
	}

	parsedURL, err := url.Parse(reqURL)
	if err != nil {
		lg.Error("failed to parse base url", "error", err)
		return false, err
	}
	q := parsedURL.Query()
	q.Set("override", "false")
	parsedURL.RawQuery = q.Encode()
	finalURL := parsedURL.String()
	buf, err := json.Marshal(body)
	if err != nil {
		lg.Error("Failed to marshal zscaler payload to JSON", "error", err)
		return false, err
	}

	// Retry strategy for 429 Too Many Requests
	const maxRetries = 5
	baseDelay := 500 * time.Millisecond

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Create a fresh request for each attempt
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, finalURL, bytes.NewBuffer(buf))
		if err != nil {
			lg.Error("Failed to create zscaler request", "error", err)
			return false, err
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
		req.Header.Set("Content-Type", "application/json")

		resp, err := zscaler.HTTP.Do(req)
		if err != nil {
			// Transport error; backoff unless context cancelled
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			lg.Error("Zscaler request error", "attempt", attempt, "error", err)
			delay := baseDelay * time.Duration(1<<attempt)
			delay += time.Duration(rand.Intn(250)) * time.Millisecond
			if delay > 10*time.Second {
				delay = 10 * time.Second
			}
			select {
			case <-time.After(delay):
				continue
			case <-ctx.Done():
				return false, ctx.Err()
			}
		}

		// Ensure the response body is closed per attempt
		// so that subsequent retries don't leak descriptors.
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			lg.Info("Zscaler API returned 2xx:", "status", resp.Status)
			resp.Body.Close()
			return true, nil
		}

		if resp.StatusCode == http.StatusTooManyRequests { // 429
			// Respect Retry-After header if present
			retryAfter := resp.Header.Get("Retry-After")
			var delay time.Duration
			if retryAfter != "" {
				if secs, parseErr := strconv.Atoi(retryAfter); parseErr == nil {
					delay = time.Duration(secs) * time.Second
				} else if when, parseErr := http.ParseTime(retryAfter); parseErr == nil {
					delay = time.Until(when)
				}
			}
			if delay <= 0 {
				delay = baseDelay * time.Duration(1<<attempt)
			}
			// Add jitter and cap maximum delay
			delay += time.Duration(rand.Intn(250)) * time.Millisecond
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
			lg.Info("Zscaler 429 received; backing off", "attempt", attempt, "delay", delay.String())
			resp.Body.Close()
			select {
			case <-time.After(delay):
				// retry next loop iteration
				continue
			case <-ctx.Done():
				return false, ctx.Err()
			}
		}

		// Non-2xx and not 429: fail fast
		lg.Error("Zscaler API returned non-2xx:", "status", resp.Status)
		resp.Body.Close()
		return false, fmt.Errorf("Zscaler non-2xx: %s", resp.Status)
	}

	return false, fmt.Errorf("Zscaler request failed after retries")
}

func ActivateChange(c *gin.Context, accessToken string, lg *slog.Logger) (bool, error) {
	ctx, cancel := context.WithTimeout(c, 30*time.Second)
	defer cancel()
	endpoint := "https://zsapi.zscalerdc.net/api/v1/status/activate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		lg.Error("Failed to create zscaler activate request", "error", err)
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		lg.Error("Zscaler activate non-2xx:", "status", resp.Status)
		return false, fmt.Errorf("zscaler activate non-2xx: %s", resp.Status)
	}
	lg.Info("Zscaler activate returned 2xx:", "status", resp.Status)
	return true, nil
}
