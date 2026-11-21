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
	"github.com/gin-gonic/gin"
)

// bindAbuseIPPayload preserves the shared error responses of the AbuseIP endpoints.
func bindAbuseIPPayload(c *gin.Context, dst any) bool {
	if err := strictBindJSON(c, dst); err != nil {
		c.JSON(400, gin.H{"Error, failed to deserialise into JSON": err.Error()})
		return false
	}
	if err := validate.Struct(dst); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Validation of AbuseIP payload failed", "details": err.Error()})
		return false
	}
	return true
}

func (a *App) IPLookup(c *gin.Context) {
	_, cancel := context.WithTimeout(c, 100*time.Second)
	defer cancel()
	var abuseIp models.ClientAbuseIPRequestPayload
	lg := middleware.GetLogger(c)
	lg.Info("ip lookup", "path", c.FullPath())
	if !bindAbuseIPPayload(c, &abuseIp) {
		return
	}
	ip := abuseIp.IP
	incidentId := abuseIp.IncidentID
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid IP address"})
		return
	}
	lg.Info("IP address parsed successfully", "ip", addr)
	if addr.IsPrivate() {
		c.JSON(200, models.ClientAbuseIPResponsePayload{
			Confidence:           "None",
			Country:              "None",
			ReportCount:          0,
			AbuseConfidenceScore: 0,
			TOR:                  false,
			Private:              true,
			IOC:                  ip,
			Exists:               false,
		})
		return
	}
	data, err := database.GetItemIOCFinder(c, a.Dynamo, ip, "AbuseIPDB", lg)
	if errors.Is(err, database.ErrNotFound) {
		lg.Info("Record not found in Database for IOC", "ip", ip)
	} else if err != nil {
		lg.Error("failed to read IOC from database", "error", err, "ip", ip)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if data != nil {
		info := data.Info
		confidence := data.MaliciousConfidence
		countryCode, _ := info["CountryCode"].(string)
		reportCount, _ := info["ReportCount"].(float64)
		score, _ := info["Score"].(float64)
		tor, _ := info["TOR"].(bool)
		c.JSON(200, models.ClientAbuseIPResponsePayload{
			Confidence:           confidence,
			Country:              countryCode,
			AbuseConfidenceScore: int(score),
			ReportCount:          int(reportCount),
			TOR:                  tor,
			Private:              false,
			IOC:                  ip,
			Exists:               true,
		})
		return
	}

	if a.AbuseIPDB == nil {
		lg.Error("abuseipdb client not configured")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	lookupResp, err := a.AbuseIPDB.CheckIP(c, ip, a.SSM, a.KMS, lg)
	if err != nil {
		lg.Error("abuseipdb lookup failed", "error", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Internal server error"})
		return
	}
	// This dereferences the data inside the pointer
	respData := lookupResp.Data
	// Store in DynamoDB for future lookups
	score := respData.AbuseConfidenceScore
	infoMap := map[string]interface{}{
		"Country":     respData.CountryName,
		"CountryCode": respData.CountryCode,
		"ReportCount": respData.TotalReports,
		"TOR":         respData.IsTor,
		"Score":       score,
	}
	confidenceLevel := models.GetMaliciousConfidenceLevel(score)
	iocEntry := &models.IOCTable{
		IOC:                 ip,
		IncidentID:          incidentId,
		IOCType:             "IPv4",
		EnrichmentSource:    "AbuseIPDB",
		MaliciousConfidence: string(confidenceLevel),
		Date:                sydneyDate(time.Now()),
		Info:                infoMap,
	}
	a.saveIOCRecord(c, lg, iocEntry)
	c.JSON(200, models.ClientAbuseIPResponsePayload{
		Confidence:           string(confidenceLevel),
		Country:              respData.CountryName,
		ReportCount:          respData.TotalReports,
		AbuseConfidenceScore: respData.AbuseConfidenceScore,
		TOR:                  respData.IsTor,
		Private:              false,
		IOC:                  ip,
		Exists:               true,
	})
}

func (a *App) ManualIPLookup(c *gin.Context) {
	_, cancel := context.WithTimeout(c, 100*time.Second)
	defer cancel()
	var abuseIp models.ManualLookupIPRequestPayload
	lg := middleware.GetLogger(c)
	lg.Info("ip manual lookup", "path", c.FullPath())
	if !bindAbuseIPPayload(c, &abuseIp) {
		return
	}
	ip := abuseIp.IP
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid IP address"})
		return
	}
	lg.Info("IP address parsed successfully", "ip", addr)
	if addr.IsPrivate() {
		c.JSON(200, models.ClientAbuseIPResponsePayload{
			Confidence:  "None",
			Country:     "None",
			ReportCount: 0,
			TOR:         false,
			Private:     true,
			IOC:         ip,
			Exists:      true,
		})
		return
	}
	data, err := database.GetItemIOCFinder(c, a.Dynamo, ip, "AbuseIPDB", lg)
	if errors.Is(err, database.ErrNotFound) {
		lg.Info("Record not found in Database for IOC", "ip", ip)
	} else if err != nil {
		lg.Error("failed to read IOC from database", "error", err, "ip", ip)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if data != nil {
		info := data.Info
		confidence := data.MaliciousConfidence
		countryCode, _ := info["CountryCode"].(string)
		reportCount, _ := info["ReportCount"].(float64)
		score, _ := info["Score"].(float64)
		tor, _ := info["TOR"].(bool)
		c.JSON(200, models.ClientAbuseIPResponsePayload{
			Confidence:           confidence,
			Country:              countryCode,
			ReportCount:          int(reportCount),
			AbuseConfidenceScore: int(score),
			TOR:                  tor,
			Private:              false,
			IOC:                  ip,
			Exists:               true,
		})
		return
	} else {
		c.JSON(200, models.ClientAbuseIPResponsePayload{
			Confidence:           "None",
			Country:              "None",
			ReportCount:          0,
			AbuseConfidenceScore: 0,
			TOR:                  false,
			Private:              false,
			IOC:                  ip,
			Exists:               false,
		})
		return
	}
}

func (a *App) ManualPutAbuseIP(c *gin.Context) {
	_, cancel := context.WithTimeout(c, 100*time.Second)
	defer cancel()
	var abuseIp models.ManualAddAbuseIPPayload
	lg := middleware.GetLogger(c)
	lg.Info("Manual Abuse IP add", "path", c.FullPath())
	if !bindAbuseIPPayload(c, &abuseIp) {
		return
	}
	ip := abuseIp.IP
	incidentID := abuseIp.IncidentID
	abuseConfidenceScore := abuseIp.AbuseConfidenceScore
	country := abuseIp.Country
	countryCode := abuseIp.CountryCode
	reportCount := abuseIp.ReportCount
	iocType := models.IOCClassifier(ip)
	infoMap := map[string]interface{}{
		"Country":     country,
		"CountryCode": countryCode,
		"ReportCount": reportCount,
		"TOR":         false,
		"Score":       abuseConfidenceScore,
	}
	confidenceLevel := models.GetMaliciousConfidenceLevel(abuseConfidenceScore)
	iocEntry := &models.IOCTable{
		IOC:                 ip,
		IncidentID:          incidentID,
		IOCType:             iocType,
		EnrichmentSource:    "AbuseIPDB",
		MaliciousConfidence: string(confidenceLevel),
		Date:                sydneyDate(time.Now()),
		Info:                infoMap,
	}
	err := database.PutItemIOCFinder(c, a.Dynamo, lg, iocEntry)
	if err != nil {
		lg.Error("failed to put item into dynamodb", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"Added": false})
		return
	}
	c.JSON(200, gin.H{"Added": true})

}
