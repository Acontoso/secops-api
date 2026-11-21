package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/Acontoso/soar-api/code/database"
	"github.com/Acontoso/soar-api/code/middleware"
	"github.com/Acontoso/soar-api/code/models"
	"github.com/Acontoso/soar-api/code/services"
	"github.com/gin-gonic/gin"
)

type CloudflareIOCResult struct {
	Response []models.CloudflareBlockIPResponsePayload
	Error    error
}

func (a *App) CloudflareBlock(c *gin.Context) {
	_, cancel := context.WithTimeout(c, 100*time.Second)
	defer cancel()
	var cloudflareBlockIP models.CloudflareBlockIPRequestPayload
	lg := middleware.GetLogger(c)
	lg.Info("Cloudflare Block IOC", "path", c.FullPath())
	if err := strictBindJSON(c, &cloudflareBlockIP); err != nil {
		respondBindError(c, lg, err)
		return
	}
	if err := validate.Struct(cloudflareBlockIP); err != nil {
		lg.Error("Validation of Cloudflare payload failed", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Validation of Cloudflare IOC block payload failed"})
		return
	}
	iocs := cloudflareBlockIP.IPs
	incidentId := cloudflareBlockIP.IncidentID
	accounts := cloudflareBlockIP.AccountNames

	existingData, err := database.GetItemsSOAR(c, a.Dynamo, iocs, "Cloudflare", lg)
	if errors.Is(err, database.ErrNotFound) {
		lg.Info("No existing records found in Database for IOCs in Cloudflare")
	} else if err != nil {
		lg.Error("failed to read existing Cloudflare IOCs from database", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Build a map of found IOCs for quick lookup
	existingRecords := make(map[string]models.SOARTable)
	for _, record := range existingData {
		existingRecords[record.IOC] = record
	}
	// Buffer one result per account so workers can finish before results are read.
	results := make(chan CloudflareIOCResult, len(accounts))
	// Start one worker per account and receive exactly one result from each below.
	for _, account := range accounts {
		go func(account string) {
			result, err := a.blockIPCloudflare(c, iocs, incidentId, account, existingRecords, lg)
			results <- CloudflareIOCResult{Response: result, Error: err}
		}(string(account))
	}
	var responses []models.CloudflareBlockIPResponsePayload
	successCount := 0
	failureCount := 0

	for i := 0; i < len(accounts); i++ {
		// Results arrive in account-completion order.
		result := <-results
		lg.Info("DEBUG: Result received", "response_length", len(result.Response), "error", result.Error)
		if result.Error != nil {
			lg.Error("failed to block IOC", "error", result.Error)
			for i := range result.Response {
				result.Response[i].Added = false
				result.Response[i].Action = "Failed"
			}
			failureCount++
		} else {
			if len(result.Response) > 0 && result.Response[0].Added {
				successCount++
			} else {
				failureCount++
			}
		}
		responses = append(responses, result.Response...)
	}
	addedAccounts := make(map[string]map[string]bool)
	for _, response := range responses {
		if response.Added {
			if addedAccounts[response.IOC] == nil {
				addedAccounts[response.IOC] = make(map[string]bool)
			}
			addedAccounts[response.IOC][response.Account] = true
		}
	}
	for _, ioc := range iocs {
		// Persist only memberships actually established for this IOC, never
		// configured/requested accounts whose Cloudflare operation failed.
		if _, exists := existingRecords[ioc]; !exists {
			var verifiedAccounts []string
			for _, account := range accounts {
				if addedAccounts[ioc][account] {
					verifiedAccounts = append(verifiedAccounts, account)
				}
			}
			if len(verifiedAccounts) == 0 {
				continue
			}
			infoMap := map[string]interface{}{
				"Accounts": verifiedAccounts,
			}
			soarEntry := &models.SOARTable{
				IOC:         ioc,
				IncidentID:  incidentId,
				Integration: "Cloudflare",
				Date:        sydneyDate(time.Now()),
				Info:        infoMap,
			}
			a.saveSOARRecord(c, lg, soarEntry)
		}
	}

	batchResponse := models.CloudflareBlockIPBatchResponsePayload{
		Results: responses,
		Summary: models.CloudflareBlockIPSummary{
			Total:     len(iocs),
			Succeeded: successCount,
			Failed:    failureCount,
		},
	}

	// Use 200 for all success, 207 for partial failure
	if failureCount == 0 {
		c.JSON(200, batchResponse)
	} else {
		c.JSON(207, batchResponse)
	}
}

// blockIPCloudflare processes one account in input order. Existing account
// memberships bypass Cloudflare; only existing records need account updates.
func (a *App) blockIPCloudflare(c *gin.Context, iocs []string, incidentID string, account string, existingRecords map[string]models.SOARTable, lg *slog.Logger) ([]models.CloudflareBlockIPResponsePayload, error) {
	var responses []models.CloudflareBlockIPResponsePayload
	for _, ioc := range iocs {
		record, exists := existingRecords[ioc]
		if exists && slices.Contains(cloudflareAccounts(record.Info), account) {
			responses = append(responses, models.CloudflareBlockIPResponsePayload{
				Added: true, IOC: ioc, Account: account, Action: "Block",
			})
			continue
		}

		added, err := services.CloudflareAddIP(c, ioc, account, incidentID, a.SSM, a.KMS, lg)
		if err != nil {
			lg.Error("Failed to add IOC to Cloudflare", "ioc", ioc, "error", err)
			responses = append(responses, models.CloudflareBlockIPResponsePayload{
				Added: false, IOC: ioc, Account: account, Action: "None",
			})
			continue
		}
		responses = append(responses, models.CloudflareBlockIPResponsePayload{
			Added: added, IOC: ioc, Account: account, Action: "Block",
		})

		// New records are written by CloudflareBlock after all account results.
		if exists && added {
			if err := database.UpdateItemSOARAccounts(c, a.Dynamo, lg, ioc, "Cloudflare", account); err != nil {
				lg.Error("Failed to update SOAR database with new Cloudflare account", "ioc", ioc, "account", account, "error", err)
			}
		}
	}
	return responses, nil
}

// cloudflareAccounts accepts both native and DynamoDB-decoded string lists.
func cloudflareAccounts(info map[string]interface{}) []string {
	if accounts, ok := info["Accounts"].([]string); ok {
		return accounts
	}
	var accounts []string
	if values, ok := info["Accounts"].([]interface{}); ok {
		for _, value := range values {
			if account, ok := value.(string); ok {
				accounts = append(accounts, account)
			}
		}
	}
	return accounts
}
