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
		respondBindError(c, lg, err)
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
	accessToken, err := a.zscalerAccessToken(ctx, c, lg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	batchResponse := a.blockZscalerIOCs(c, sseUpload.IOCs, sseUpload.IncidentID, accessToken, lg)
	_, activateErr := services.ActivateChange(c, accessToken, lg)
	if activateErr != nil {
		lg.Error("Failed to activate zscaler change", "error", activateErr)
	}
	// Use 200 for all success, 207 for partial failure
	if batchResponse.Summary.Failed == 0 {
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
		soarEntry := &models.SOARTable{
			IOC:         ioc,
			Integration: "Zscaler",
			Date:        sydneyDate(time.Now()),
			IncidentID:  incidentId,
		}
		a.saveSOARRecord(c, lg, soarEntry)
	}
	return models.SSEUploadResponsePayload{
		Added:       result,
		IOC:         ioc,
		Integration: "Zscaler",
		Action:      "Block",
	}, nil
}
