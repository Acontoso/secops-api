package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Acontoso/soar-api/code/models"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/gin-gonic/gin"
)

var WESHEALTH_SECURITY_AZ_CLIENT_ID string = "id"
var SCOPE_DATP string = "https://api.securitycenter.windows.com/.default"

func UploadIOCToDATP(c *gin.Context, ioc string, tenantID string, action models.Action, incidentID string, cognitoClient *cognitoidentity.Client, lg *slog.Logger) (bool, error) {
	ctx, cancel := context.WithTimeout(c, 20*time.Second)
	defer cancel()
	azureClient, err := NewAzureADClientAssertion(c, WESHEALTH_SECURITY_AZ_CLIENT_ID, tenantID, cognitoClient, lg)
	if err != nil {
		lg.Error("failed to create Azure AD client", "error", err)
		return false, err
	}
	accessToken, err := azureClient.GetAccessTokenSecret(ctx, SCOPE_DATP)
	if err != nil {
		lg.Error("failed to get access token for DATP", "error", err)
		return false, err
	}
	iocType := models.IOCClassifier(ioc)
	indicator, err := checkIndicatorDATP(c, ioc, accessToken, iocType, lg)
	if err != nil {
		lg.Error("Failed to check indicator in DATP", "error", err)
		return false, err
	}
	if indicator {
		return true, nil
	}
	epochSeconds := time.Now().Unix()
	epochStr := strconv.FormatInt(epochSeconds, 10)
	payload := models.DATPUpdatePayload{
		IndicatorValue: ioc,
		IndicatorType:  convertToDATPIOC(iocType),
		Action:         action,
		Description:    fmt.Sprintf("SOAR API Automated Response - %s", incidentID),
		Title:          fmt.Sprintf("SOARAPI-%s-%s-%s", incidentID, iocType, epochStr),
		GenerateAlert:  true,
		ExpirationTime: time.Now().UTC().Add(52 * 7 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339),
		Severity:       "High",
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		lg.Error("Failed to marshal DATP payload", "error", err)
		return false, err
	}
	parsedURL, err := url.Parse("https://api.securitycenter.microsoft.com/api/indicators")
	if err != nil {
		lg.Error("Failed to parse DATP url", "error", err)
		return false, err
	}
	finalURL := parsedURL.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, finalURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		lg.Error("Failed to create DATP request", "error", err)
		return false, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		lg.Error("DATP request failed", "error", err)
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		lg.Error("DATP API returned non-2xx:", "status", resp.Status)
		return false, fmt.Errorf("DATP non-2xx: %s", resp.Status)
	}
	lg.Info("DATP API returned 2xx:", "status", resp.Status)
	return true, nil
}

func checkIndicatorDATP(c *gin.Context, ioc string, accessToken string, iocType string, lg *slog.Logger) (bool, error) {
	ctx, cancel := context.WithTimeout(c, 20*time.Second)
	defer cancel()
	datpType := convertToDATPIOC(iocType)
	if datpType == "" {
		lg.Error("Unsupported IOC type for DATP", "iocType", iocType)
		return false, fmt.Errorf("Unsupported IOC type for DATP: %s", iocType)
	}
	parsedURL, err := url.Parse("https://api.securitycenter.microsoft.com/api/indicators")
	if err != nil {
		lg.Error("Failed to parse base url", "error", err)
		return false, err
	}
	q := parsedURL.Query()
	q.Set("$filter", fmt.Sprintf("indicatorValue eq '%s'", ioc))
	parsedURL.RawQuery = q.Encode()
	finalURL := parsedURL.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, finalURL, nil)
	if err != nil {
		lg.Error("Failed to create DATP request", "error", err)
		return false, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Accept", "application/json")

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		lg.Error("DATP request failed", "error", err)
		return false, err
	}
	defer resp.Body.Close()
	// Read response body as io.Reader - then convert to string
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		lg.Error("Failed to read DATP response", "error", err)
		return false, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		lg.Error("DATP non-2xx", "status", resp.Status, "body", string(body))
		return false, fmt.Errorf("DATP non-2xx: %s", resp.Status)
	}

	var out struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		lg.Error("Failed to unmarshal DATP response", "error", err)
		return false, err
	}

	return len(out.Value) > 0, nil
}

func convertToDATPIOC(iocType string) string {
	switch iocType {
	case "IPv4":
		return "IpAddress"
	case "Domain":
		return "DomainName"
	case "MD5":
		return "FileMd5"
	case "SHA1":
		return "FileSha1"
	case "SHA256":
		return "FileSha256"
	default:
		return ""
	}
}
