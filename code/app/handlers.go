package app

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/Acontoso/soar-api/code/database"
	"github.com/Acontoso/soar-api/code/middleware"
	"github.com/Acontoso/soar-api/code/models"
	"github.com/Acontoso/soar-api/code/services"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

func (a *App) AnomaliLookup(c *gin.Context) {
	_, cancel := context.WithTimeout(c, 100*time.Second)
	defer cancel()
	var anomaliLookup models.AnomaliRequestPayload
	lg := middleware.GetLogger(c)
	lg.Info("anomali lookup", "path", c.FullPath())
	if err := strictBindJSON(c, &anomaliLookup); err != nil {
		lg.Error("Error, failed to deserialise into JSON", "error", err)
		c.JSON(400, gin.H{"Error": "Payload failed to deserialise into JSON"})
		return
	}
	if err := validate.Struct(anomaliLookup); err != nil {
		lg.Error("Validation of Anomali payload failed", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Validation of Anomali payload failed"})
		return
	}
	ioc := anomaliLookup.IOC
	incidentId := anomaliLookup.IncidentID
	data, err := database.GetItemIOCFinder(c, a.Dynamo, ioc, "Anomali", lg)
	if errors.Is(err, database.ErrNotFound) {
		lg.Info("Record not found in Database for IOC", "ioc", ioc)
	} else if err != nil {
		lg.Error("failed to read IOC from database", "error", err, "ioc", ioc)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if data != nil {
		lg.Info("Existing record found for IOC", "ioc", ioc)
		info := data.Info
		confidence := data.MaliciousConfidence
		iocType := data.IOCType
		// DynamoDB numbers unmarshal as float64
		score := 0
		if scoreVal, ok := info["Score"]; ok {
			switch v := scoreVal.(type) {
			case float64:
				score = int(v)
			case int:
				score = v
			}
		}
		c.JSON(200, models.AnomaliResponsePayload{
			Confidence: confidence,
			IOCType:    iocType,
			IOC:        ioc,
			Score:      score,
		})
		return
	}
	iocType := models.IOCClassifier(ioc)
	if iocType == "IPv4" || iocType == "IPv6" {
		addr, err := netip.ParseAddr(ioc)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid IP address"})
			return
		}
		lg.Info("IP address parsed successfully", "ip", addr)
		if addr.IsPrivate() {
			c.JSON(200, models.AnomaliResponsePayload{
				Confidence: "None",
				IOCType:    iocType,
				IOC:        ioc,
				Score:      0,
			})
			return
		}
	}
	confidence, err := a.Anomali.CheckIOC(c, ioc, a.SSM, a.KMS, lg)
	if err != nil {
		lg.Error("anomali lookup failed", "error", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Internal server error"})
		return
	}
	confidenceLevel := models.GetMaliciousConfidenceLevel(confidence)
	loc, _ := time.LoadLocation("Australia/Sydney")
	iocEntry := &models.IOCTable{
		IOC:                 ioc,
		IncidentID:          incidentId,
		IOCType:             iocType,
		EnrichmentSource:    "Anomali",
		MaliciousConfidence: string(confidenceLevel),
		Date:                time.Now().In(loc).Format("02-01-2006"),
		Info: map[string]interface{}{
			"Score": confidence,
		},
	}
	err = database.PutItemIOCFinder(c, a.Dynamo, lg, iocEntry)
	if err != nil {
		lg.Error("failed to put item into dynamodb", "error", err)
		// continue even if we fail to store
	}
	c.JSON(200, models.AnomaliResponsePayload{
		Confidence: string(confidenceLevel),
		IOCType:    iocType,
		IOC:        ioc,
		Score:      confidence,
	})
}

func (a *App) CABlock(c *gin.Context) {
	_, cancel := context.WithTimeout(c, 100*time.Second)
	defer cancel()
	var calist models.AzureADCARequestPayload
	lg := middleware.GetLogger(c)
	lg.Info("Conditional Access Block IP", "path", c.FullPath())
	if err := strictBindJSON(c, &calist); err != nil {
		lg.Error("Error, failed to deserialise into JSON", "error", err)
		c.JSON(400, gin.H{"Error": "Payload failed to deserialise into JSON"})
		return
	}
	if err := validate.Struct(calist); err != nil {
		lg.Error("Validation of SSE payload failed", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Validation of SSE IOC block payload failed"})
		return
	}
	ioc := calist.IOC
	incidentId := calist.IncidentID
	tenantID := calist.TenantID
	listID := calist.ListID
	data, err := database.GetItemSOAR(c, a.Dynamo, ioc, "AzureAD", lg)
	if errors.Is(err, database.ErrNotFound) {
		lg.Info("Record not found in Database for IOC", "ioc", ioc)
	} else if err != nil {
		lg.Error("failed to read SOAR IOC from database", "error", err, "ioc", ioc)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if data != nil {
		lg.Info("Existing record found for IOC", "ioc", ioc)
		c.JSON(200, models.AzureADCAResponsePayload{
			IOC:      ioc,
			ListName: "SOAR-API-Locations",
			Action:   "Block",
		})
		return
	}
	iocType := models.IOCClassifier(ioc)
	if iocType == "IPv4" || iocType == "IPv6" {
		addr, err := netip.ParseAddr(ioc)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid IP address"})
			return
		}
		lg.Info("IP address parsed successfully", "ip", addr)
		if addr.IsPrivate() {
			c.JSON(200, models.AzureADCAResponsePayload{
				IOC:      ioc,
				ListName: "SOAR-API-Locations",
				Action:   "None",
			})
			return
		}
	} else {
		c.JSON(400, gin.H{"error": "Not valid IP Address"})
		return
	}
	result, err := services.UpdateCAList(c, ioc, tenantID, listID, a.SSM, a.KMS, a.Cognito, lg)
	if err != nil {
		lg.Error("AzureAD IOC block failed", "error", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Internal server error"})
		return
	}
	if result {
		loc, _ := time.LoadLocation("Australia/Sydney")
		soarEntry := &models.SOARTable{
			IOC:         ioc,
			Integration: "AzureAD",
			Date:        time.Now().In(loc).Format("02-01-2006"),
			IncidentID:  incidentId,
			Info: map[string]interface{}{
				"TenantID": tenantID,
				"ListID":   listID,
				"ListName": "SOAR-API-Locations",
			},
		}
		err = database.PutItemSOAR(c, a.Dynamo, lg, soarEntry)
		if err != nil {
			lg.Error("failed to put item into dynamodb", "error", err)
			// continue even if we fail to store
		}
	}
	c.JSON(200, models.AzureADCAResponsePayload{
		IOC:      ioc,
		ListName: "SOAR-API-Locations",
		Action:   "Block",
	})
}

func (a *App) DATPBlock(c *gin.Context) {
	_, cancel := context.WithTimeout(c, 100*time.Second)
	defer cancel()
	var datp models.DATPUploadRequestPayload
	lg := middleware.GetLogger(c)
	lg.Info("DATP Block IOC", "path", c.FullPath())
	if err := strictBindJSON(c, &datp); err != nil {
		lg.Error("Error, failed to deserialise into JSON", "error", err)
		c.JSON(400, gin.H{"Error": "Payload failed to deserialise into JSON"})
		return
	}
	if err := validate.Struct(datp); err != nil {
		lg.Error("Validation of SSE payload failed", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Validation of SSE IOC block payload failed"})
		return
	}
	ioc := datp.IOC
	incidentId := datp.IncidentID
	tenantID := datp.TenantID
	action := datp.Action
	data, err := database.GetItemSOAR(c, a.Dynamo, ioc, "DATP", lg)
	if errors.Is(err, database.ErrNotFound) {
		lg.Info("Record not found in Database for IOC", "ioc", ioc)
	} else if err != nil {
		lg.Error("failed to read SOAR IOC from database", "error", err, "ioc", ioc)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if data != nil {
		lg.Info("Existing record found for IOC", "ioc", ioc)
		c.JSON(200, models.DATPUploadResponsePayload{
			IOC:      ioc,
			Platform: "DATP",
			Action:   action,
			Added:    true,
		})
		return
	}
	result, err := services.UploadIOCToDATP(c, ioc, tenantID, action, incidentId, a.Cognito, lg)
	if err != nil {
		lg.Error("AzureAD IOC block failed", "error", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Internal server error"})
		return
	}
	if result {
		loc, _ := time.LoadLocation("Australia/Sydney")
		soarEntry := &models.SOARTable{
			IOC:         ioc,
			Integration: "DATP",
			Date:        time.Now().In(loc).Format("02-01-2006"),
			IncidentID:  incidentId,
		}
		err = database.PutItemSOAR(c, a.Dynamo, lg, soarEntry)
		if err != nil {
			lg.Error("failed to put item into dynamodb", "error", err)
			// continue even if we fail to store
		}
	}
	c.JSON(200, models.DATPUploadResponsePayload{
		IOC:      ioc,
		Platform: "DATP",
		Action:   action,
		Added:    true,
	})
}
