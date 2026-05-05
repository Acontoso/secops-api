package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/Acontoso/soar-api/code/database"
	"github.com/Acontoso/soar-api/code/middleware"
	"github.com/Acontoso/soar-api/code/models"
	"github.com/Acontoso/soar-api/code/services"
	"github.com/gin-gonic/gin"
)

type SSEIOCResult struct {
	Response models.SSEUploadResponsePayload
	Error    error
}

var SCOPE string = "api://6c96f6a7-8e7a-4dd5-8a2b-46bf6100a3bd/.default"

func (a *App) SSEBlock(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c, 100*time.Second)
	defer cancel()
	var sseUpload models.SSEUploadRequestPayload
	lg := middleware.GetLogger(c)
	lg.Info("Zscaler Block IOC", "path", c.FullPath())
	if err := strictBindJSON(c, &sseUpload); err != nil {
		lg.Error("Error, failed to deserialise into JSON", "error", err)
		c.JSON(400, gin.H{"Error": "Payload failed to deserialise into JSON"})
		return
	}
	if err := validate.Struct(sseUpload); err != nil {
		lg.Error("Validation of SSE payload failed", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Validation of SSE IOC block payload failed"})
		return
	}
	if a.Zscaler == nil {
		lg.Error("Zscaler client not configured")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	iocs := sseUpload.IOCs
	incidentId := sseUpload.IncidentID
	zscalerClientID, err := services.GetParam(c, a.SSM, a.KMS, "zscaler_client_id", lg)
	if err != nil {
		lg.Error("failed to get zscaler client id", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	zscalerClientSecret, err := services.GetParam(c, a.SSM, a.KMS, "zscaler_client_secret", lg)
	if err != nil {
		lg.Error("failed to get zscaler client secret", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	AzureADClient, err := services.NewAzureADClient(zscalerClientID, zscalerClientSecret, lg)
	if err != nil {
		lg.Error("failed to create AzureAD client", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	accessToken, err := AzureADClient.GetAccessTokenSecret(ctx, SCOPE)
	if err != nil {
		lg.Error("Failed to get access token from Azure AD", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	// Channel to collect results
	results := make(chan SSEIOCResult, len(iocs))
	// Process each IOC concurrently
	for _, ioc := range iocs {
		go func(ioc string) {
			result, err := a.blockSingleIOC(c, ioc, incidentId, accessToken, lg)
			// Passes the result /value back to a channel
			// Critical: The number of goroutines must match the number of times you read from the channel
			results <- SSEIOCResult{Response: result, Error: err}
		}(ioc)
	}
	var responses []models.SSEUploadResponsePayload
	successCount := 0
	failureCount := 0

	for i := 0; i < len(iocs); i++ {
		// This will block until a result is available, go routine has completed execution
		// the <- means receive from channel that was passed from go routine back into the main function
		result := <-results
		if result.Error != nil {
			lg.Error("failed to block IOC", "error", result.Error)
			result.Response.Added = false
			result.Response.Action = "Failed"
			failureCount++
		} else if result.Response.Added {
			successCount++
		} else {
			failureCount++
		}
		responses = append(responses, result.Response)
	}
	_, activateErr := services.ActivateChange(c, accessToken, lg)
	if activateErr != nil {
		lg.Error("Failed to activate zscaler change", "error", activateErr)
	}
	batchResponse := models.SSEUploadBatchResponsePayload{
		Results: responses,
		Summary: models.SSEUploadSummary{
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

func (a *App) blockSingleIOC(c *gin.Context, ioc string, incidentId string, accessToken string, lg *slog.Logger) (models.SSEUploadResponsePayload, error) {
	data, err := database.GetItemSOAR(c, a.Dynamo, ioc, "Zscaler", lg)
	if errors.Is(err, database.ErrNotFound) {
		lg.Info("Record not found in Database for IOC", "ioc", ioc)
	} else if err != nil {
		lg.Error("failed to read IOC from database", "error", err, "ioc", ioc)
		return models.SSEUploadResponsePayload{
			Added:       false,
			IOC:         ioc,
			Integration: "Zscaler",
			Action:      "Failed",
		}, fmt.Errorf("database error for IOC %s", ioc)
	}
	if data != nil {
		lg.Info("Existing record found for IOC", "ioc", ioc)
		return models.SSEUploadResponsePayload{
			Added:       true,
			IOC:         ioc,
			Integration: "Zscaler",
			Action:      "Block",
		}, nil
	}
	iocType := models.IOCClassifier(ioc)
	if iocType == "IPv4" || iocType == "IPv6" {
		addr, err := netip.ParseAddr(ioc)
		if err != nil {
			return models.SSEUploadResponsePayload{
				Added:       false,
				IOC:         ioc,
				Integration: "Zscaler",
				Action:      "None",
			}, fmt.Errorf("Invalid IP address %s", ioc)
		}
		lg.Info("IP address parsed successfully", "ip", addr)
		if addr.IsPrivate() {
			return models.SSEUploadResponsePayload{
				Added:       false,
				IOC:         ioc,
				Integration: "Zscaler",
				Action:      "None",
			}, fmt.Errorf("IP Address %s is private", ioc)
		}
	}
	result, err := a.Zscaler.BlockIOC(c, ioc, accessToken, lg)
	if err != nil {
		lg.Error("Zscaler IOC block failed", "error", err)
		return models.SSEUploadResponsePayload{
			Added:       false,
			IOC:         ioc,
			Integration: "Zscaler",
			Action:      "None",
		}, fmt.Errorf("Internal server error for IOC %s", ioc)
	}
	if result {
		loc, _ := time.LoadLocation("Australia/Sydney")
		soarEntry := &models.SOARTable{
			IOC:         ioc,
			Integration: "Zscaler",
			Date:        time.Now().In(loc).Format("02-01-2006"),
			IncidentID:  incidentId,
		}
		err = database.PutItemSOAR(c, a.Dynamo, lg, soarEntry)
		if err != nil {
			lg.Error("failed to put item into dynamodb", "error", err)
			// continue even if we fail to store
		}
	}
	return models.SSEUploadResponsePayload{
		Added:       result,
		IOC:         ioc,
		Integration: "Zscaler",
		Action:      "Block",
	}, nil
}
