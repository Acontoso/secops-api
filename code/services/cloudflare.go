package services

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/cloudflare/cloudflare-go"
	"github.com/gin-gonic/gin"
)

var ListMap = map[string]string{}

var AccountIDMap = map[string]string{}

func NewCloudflareClient(apiToken string) (*cloudflare.API, error) {
	return cloudflare.NewWithAPIToken(apiToken)
}

// CheckIP queries AbuseIPDB for a single IP.
func CloudflareAddIP(c *gin.Context, ip string, account string, incidentID string, ssmClient *ssm.Client, kmsClient *kms.Client, lg *slog.Logger) (bool, error) {
	ctx, cancel := context.WithTimeout(c, 30*time.Second)
	defer cancel()
	accountID, ok := AccountIDMap[account]
	if !ok {
		lg.Error("Cloudflare account not found in map", "account", account)
		return false, nil
	}
	list, ok := ListMap[account]
	if !ok {
		lg.Error("Cloudflare list not found in map", "account", account)
		return false, nil
	}
	cloudflareAPIToken, err := GetParam(c, ssmClient, kmsClient, account, lg)
	if err != nil {
		lg.Error("failed to get cloudflare api token", "error", err)
		return false, nil
	}
	api, err := NewCloudflareClient(cloudflareAPIToken)
	if err != nil {
		lg.Error("failed to create cloudflare client", "error", err)
		return false, err
	}
	lg.Info("Adding to list %s IOC %s", "list", list, "ip", ip)
	items := []cloudflare.ListItemCreateRequest{
		{
			IP:      &ip,
			Comment: fmt.Sprintf("Added via SOAR Incident %s", incidentID),
		},
	}
	_, err = api.CreateListItems(ctx, cloudflare.AccountIdentifier(accountID), cloudflare.ListCreateItemsParams{
		ID:    list,
		Items: items,
	})
	if err != nil {
		lg.Error("failed to add IP to cloudflare list", "error", err)
		return false, err
	}
	return true, nil
}
