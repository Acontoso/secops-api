package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/Acontoso/soar-api/code/models"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/gin-gonic/gin"
)

// var TENANTID string = os.Getenv("TENANT_ID")
var WH_TENANTID string = os.Getenv("TENANT_ID")
var MA_TENANTID string = os.Getenv("TENANT_ID_MA")
var WESHEALTH_GRAPH_AZ_CLIENT_ID string = os.Getenv("WESHEALTH_GRAPH_AZ_CLIENT_ID")
var WESHEALTH_MA_GRAPH_AZ_CLIENT_ID string = os.Getenv("WESHEALTH_MA_GRAPH_AZ_CLIENT_ID")
var WH_LIST_ID string = os.Getenv("WH_LIST_ID")
var MA_LIST_ID string = os.Getenv("MA_LIST_ID")
var LISTNAME string = os.Getenv("LISTNAME")

type AzureADCA struct {
	clientID string
	ListID   string
	TenantID string
}

type AzureADClient struct {
	clientID     string
	clientSecret string
	tenantID     string
	credential   azcore.TokenCredential
}

func NewAzureADClient(clientID string, clientSecret string, lg *slog.Logger) (*AzureADClient, error) {
	credential, err := azidentity.NewClientSecretCredential(WH_TENANTID, clientID, clientSecret, nil)
	if err != nil {
		lg.Error("Failed to create Azure AD client secret credential", "error", err)
		return nil, err
	}
	return &AzureADClient{
		clientID:     clientID,
		clientSecret: clientSecret,
		tenantID:     WH_TENANTID,
		credential:   credential,
	}, nil
}

func (client *AzureADClient) GetAccessTokenSecret(ctx context.Context, scope string) (string, error) {
	if scope == "" {
		return "", fmt.Errorf("scope is required")
	}

	// Request token with the specified scope
	token, err := client.credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{scope},
	})
	if err != nil {
		return "", fmt.Errorf("failed to acquire access token: %w", err)
	}

	return token.Token, nil
}

func NewAzureADClientAssertion(c *gin.Context, clientID string, tenantID string, cognitoClient *cognitoidentity.Client, lg *slog.Logger) (*AzureADClient, error) {
	credential, err := azidentity.NewClientAssertionCredential(tenantID, clientID, func(ctx context.Context) (string, error) {
		cognitoToken, err := GetCognitoToken(c, cognitoClient, lg)
		if err != nil {
			lg.Error("Failed to get cognito token, cant return assertion for Azure AD token", "error", err)
			return "", err
		}
		return cognitoToken, nil
	}, nil)
	if err != nil {
		lg.Error("Failed to create Azure AD client assertion credential", "error", err)
		return nil, err
	}
	return &AzureADClient{
		clientID:     clientID,
		clientSecret: "",
		tenantID:     tenantID,
		credential:   credential,
	}, nil

}

func UpdateCAList(c *gin.Context, ioc string, tenant_id string, list_id string, ssmClient *ssm.Client, kmsClient *kms.Client, cognitoClient *cognitoidentity.Client, lg *slog.Logger) (bool, error) {
	ctx, cancel := context.WithTimeout(c, 20*time.Second)
	defer cancel()
	var ca AzureADCA
	if tenant_id == WH_TENANTID {
		ca = AzureADCA{
			clientID: WESHEALTH_GRAPH_AZ_CLIENT_ID,
			ListID:   WH_LIST_ID,
			TenantID: WH_TENANTID,
		}
	}
	if tenant_id == MA_TENANTID {
		ca = AzureADCA{
			clientID: WESHEALTH_MA_GRAPH_AZ_CLIENT_ID,
			ListID:   MA_LIST_ID,
			TenantID: MA_TENANTID,
		}

	}
	client, err := NewAzureADClientAssertion(c, ca.clientID, ca.TenantID, cognitoClient, lg)
	if err != nil {
		lg.Error("Failed to create AzureAD client", "error", err)
		return false, err
	}
	token, err := client.GetAccessTokenSecret(ctx, "https://graph.microsoft.com/.default")
	if err != nil {
		lg.Error("Failed to get access token secret", "error", err)
		return false, err
	}
	getURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations/%s", list_id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		lg.Error("Failed to create get named location request", "error", err)
		return false, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		lg.Error("Failed to get named location", "error", err)
		return false, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		lg.Error("Failed to read GET response body", "error", err)
		return false, err
	}

	var location models.NamedLocation
	if err := json.Unmarshal(bodyBytes, &location); err != nil {
		lg.Error("Failed to decode named location response", "error", err)
		return false, err
	}
	lg.Info("Retrieved named location")

	var existingIPRanges []models.IPRange
	if location.OdataType == "#microsoft.graph.ipNamedLocation" {
		existingIPRanges = append(existingIPRanges, location.IPRanges...)
	}

	iocWithCIDR := ioc
	iocWithCIDR = ioc + "/32"
	newIP := models.IPRange{
		OdataType:   "#microsoft.graph.iPv4CidrRange",
		CIDRAddress: iocWithCIDR,
	}
	existingIPRanges = append(existingIPRanges, newIP)

	// Build the payload with updated IP ranges - include @odata.type for each range and root level
	var ipRangesForUpdate []map[string]string
	for _, ipRange := range existingIPRanges {
		ipRangesForUpdate = append(ipRangesForUpdate, map[string]string{
			"@odata.type": ipRange.OdataType,
			"cidrAddress": ipRange.CIDRAddress,
		})
	}

	updateBody := map[string]interface{}{
		"@odata.type": "#microsoft.graph.ipNamedLocation",
		"ipRanges":    ipRangesForUpdate,
	}
	buf, err := json.Marshal(updateBody)
	if err != nil {
		lg.Error("Failed to marshal update payload to JSON", "error", err)
		return false, err
	}
	updateURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations/%s", list_id)
	req, err = http.NewRequestWithContext(ctx, http.MethodPatch, updateURL, bytes.NewBuffer(buf))
	if err != nil {
		lg.Error("Failed to create update named location request", "error", err)
		return false, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	resp, err = (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		lg.Error("Failed to update named location", "error", err)
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		lg.Error("AzureAD non-2xx:", "status", resp.Status, "body", string(body))
		return false, fmt.Errorf("AzureAD non-2xx: %s - %s", resp.Status, string(body))
	}
	return true, nil
}
