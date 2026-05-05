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
		lg.Error("Error, failed to deserialise into JSON", "error", err)
		c.JSON(400, gin.H{"Error": "Payload failed to deserialise into JSON"})
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
	// Channel to collect results, like a pipe for passing values safetly between go routines
	// Below defines the channel to pass CloudflareIOCResult structs
	results := make(chan CloudflareIOCResult, len(accounts))
	// Process each account concurrently, straight away called by go func(), anon function in this case.
	for _, account := range accounts {
		go func(account string) {
			result, err := a.blockIPCloudflare(c, iocs, incidentId, account, existingRecords, lg)
			// Passes the result /value back to a channel, if there is blockage here the program will hang.
			// Critical: The number of goroutines must match the number of times you read from the channel
			results <- CloudflareIOCResult{Response: result, Error: err}
		}(string(account)) //straight away called by go func(), anon function in this case.
	}
	var responses []models.CloudflareBlockIPResponsePayload
	successCount := 0
	failureCount := 0

	for i := 0; i < len(accounts); i++ {
		// This recieves one value at a time, and is looped based on the amount of goroutines started above.
		// Passes the result back to the main channel
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
	loc, _ := time.LoadLocation("Australia/Sydney")
	for _, ioc := range iocs {
		// If no existing record, add to SOAR DB after initial operation done
		if _, exists := existingRecords[ioc]; !exists {
			infoMap := map[string]interface{}{
				"Accounts": accounts,
			}
			soarEntry := &models.SOARTable{
				IOC:         ioc,
				IncidentID:  incidentId,
				Integration: "Cloudflare",
				Date:        time.Now().In(loc).Format("02-01-2006"),
				Info:        infoMap,
			}
			err = database.PutItemSOAR(c, a.Dynamo, lg, soarEntry)
			if err != nil {
				lg.Error("failed to put item into dynamodb", "error", err)
			}
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

func (a *App) blockIPCloudflare(c *gin.Context, iocs []string, incidentId string, account string, existingRecords map[string]models.SOARTable, lg *slog.Logger) ([]models.CloudflareBlockIPResponsePayload, error) {
	var responses []models.CloudflareBlockIPResponsePayload
	for _, ioc := range iocs {
		if record, ok := existingRecords[ioc]; ok {
			info := record.Info
			var accounts []string
			if acc, ok := info["Accounts"].([]string); ok {
				accounts = acc
			} else if acc, ok := info["Accounts"].([]interface{}); ok {
				for _, v := range acc {
					if s, ok := v.(string); ok {
						accounts = append(accounts, s)
					}
				}
			}
			if slices.Contains(accounts, account) {
				responses = append(responses, models.CloudflareBlockIPResponsePayload{
					Added:   true,
					IOC:     ioc,
					Account: account,
					Action:  "Block",
				})
			} else {
				added, err := services.CloudflareAddIP(c, ioc, account, incidentId, a.SSM, a.KMS, lg)
				if err != nil {
					lg.Error("Failed to add IOC to Cloudflare", "ioc", ioc, "error", err)
					responses = append(responses, models.CloudflareBlockIPResponsePayload{
						Added:   false,
						IOC:     ioc,
						Account: account,
						Action:  "None",
					})
				} else {
					responses = append(responses, models.CloudflareBlockIPResponsePayload{
						Added:   added,
						IOC:     ioc,
						Account: account,
						Action:  "Block",
					})
					err = database.UpdateItemSOARAccounts(c, a.Dynamo, lg, ioc, "Cloudflare", account)
					if err != nil {
						lg.Error("Failed to update SOAR database with new Cloudflare account", "ioc", ioc, "account", account, "error", err)
					}
				}
			}
		} else {
			// New IOC - just add to Cloudflare, database write happens in main function
			added, err := services.CloudflareAddIP(c, ioc, account, incidentId, a.SSM, a.KMS, lg)
			if err != nil {
				lg.Error("Failed to add IOC to Cloudflare", "ioc", ioc, "error", err)
				responses = append(responses, models.CloudflareBlockIPResponsePayload{
					Added:   false,
					IOC:     ioc,
					Account: account,
					Action:  "None",
				})
			} else {
				responses = append(responses, models.CloudflareBlockIPResponsePayload{
					Added:   added,
					IOC:     ioc,
					Account: account,
					Action:  "Block",
				})
			}
		}
	}
	return responses, nil
}
