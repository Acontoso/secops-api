package app

import (
	"context"
	"log/slog"

	"github.com/Acontoso/soar-api/code/models"
	"github.com/Acontoso/soar-api/code/services"
	"github.com/gin-gonic/gin"
)

func (a *App) zscalerAccessToken(ctx context.Context, c *gin.Context, lg *slog.Logger) (string, error) {
	clientID, err := services.GetParam(c, a.SSM, a.KMS, "zscaler_client_id", lg)
	if err != nil {
		lg.Error("failed to get zscaler client id", "error", err)
		return "", err
	}
	clientSecret, err := services.GetParam(c, a.SSM, a.KMS, "zscaler_client_secret", lg)
	if err != nil {
		lg.Error("failed to get zscaler client secret", "error", err)
		return "", err
	}
	client, err := services.NewAzureADClient(clientID, clientSecret, lg)
	if err != nil {
		lg.Error("failed to create AzureAD client", "error", err)
		return "", err
	}
	token, err := client.GetAccessTokenSecret(ctx, SCOPE)
	if err != nil {
		lg.Error("Failed to get access token from Azure AD", "error", err)
		return "", err
	}
	return token, nil
}

// blockZscalerIOCs retains the endpoint's one-worker-per-IOC processing and
// completion-order results. Activation remains a separate step in SSEBlock.
func (a *App) blockZscalerIOCs(c *gin.Context, iocs []string, incidentID, accessToken string, lg *slog.Logger) models.SSEUploadBatchResponsePayload {
	results := make(chan SSEIOCResult, len(iocs))
	for _, ioc := range iocs {
		go func(ioc string) {
			response, err := a.blockSingleIOC(c, ioc, incidentID, accessToken, lg)
			results <- SSEIOCResult{Response: response, Error: err}
		}(ioc)
	}

	var responses []models.SSEUploadResponsePayload
	succeeded, failed := 0, 0
	for range iocs {
		result := <-results
		if result.Error != nil {
			lg.Error("failed to block IOC", "error", result.Error)
			result.Response.Added = false
			result.Response.Action = "Failed"
			failed++
		} else if result.Response.Added {
			succeeded++
		} else {
			failed++
		}
		responses = append(responses, result.Response)
	}
	return models.SSEUploadBatchResponsePayload{
		Results: responses,
		Summary: models.SSEUploadSummary{Total: len(iocs), Succeeded: succeeded, Failed: failed},
	}
}
