package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Acontoso/soar-api/code/database"
	"github.com/Acontoso/soar-api/code/middleware"
	"github.com/Acontoso/soar-api/code/models"
	"github.com/gin-gonic/gin"
)

func (a *App) RecordedFutureSOAR(c *gin.Context) {
	_, cancel := context.WithTimeout(c, 100*time.Second)
	defer cancel()
	var successCount int = 0
	var failureCount int = 0
	var recordedFutureSOAR models.RecordSOARRequestPayload
	lg := middleware.GetLogger(c)
	lg.Info("Recorded Future SOAR endpoint hit", "path", c.FullPath())
	if err := strictBindJSON(c, &recordedFutureSOAR); err != nil {
		lg.Error("Error, failed to deserialise into JSON", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"Error": "Payload failed to deserialise into JSON"})
		return
	}
	if err := validate.Struct(recordedFutureSOAR); err != nil {
		lg.Error("Validation of Recorded Future SOAR payload failed", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Validation of Recorded Future SOAR payload failed"})
		return
	}
	ips := recordedFutureSOAR.IPs
	domains := recordedFutureSOAR.Domains
	hashes := recordedFutureSOAR.Hashes
	incidentId := recordedFutureSOAR.IncidentID

	// Initialize nil slices to empty slices to handle optional fields
	if domains == nil {
		domains = []string{}
	}
	if hashes == nil {
		hashes = []string{}
	}
	if ips == nil {
		ips = []string{}
	}

	// Check each list and perform GetItemsSOAR lookups only on non-empty lists
	var existingData []models.IOCTable
	foundIOCs := make(map[string]bool)

	if len(ips) > 0 {
		data, err := database.GetItemsIOCFinder(c, a.Dynamo, ips, "RecordedFuture", lg)
		if errors.Is(err, database.ErrNotFound) {
			lg.Info("No existing records found in Database for IPs in Recorded Future", "error", err)
		} else if err != nil {
			lg.Error("Failed to read cached IPs from database", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		} else {
			lg.Info("Existing records found in Database for IPs in Recorded Future", "path", c.FullPath())
			existingData = append(existingData, data...)
			for _, record := range data {
				foundIOCs[record.IOC] = true
			}
		}
	}

	if len(domains) > 0 {
		data, err := database.GetItemsIOCFinder(c, a.Dynamo, domains, "RecordedFuture", lg)
		if errors.Is(err, database.ErrNotFound) {
			lg.Info("No existing records found in Database for Domains in Recorded Future", "error", err)
		} else if err != nil {
			lg.Error("Failed to read cached domains from database", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		} else {
			lg.Info("Existing records found in Database for Domains in Recorded Future", "path", c.FullPath())
			existingData = append(existingData, data...)
			for _, record := range data {
				foundIOCs[record.IOC] = true
			}
		}
	}

	if len(hashes) > 0 {
		data, err := database.GetItemsIOCFinder(c, a.Dynamo, hashes, "RecordedFuture", lg)
		if errors.Is(err, database.ErrNotFound) {
			lg.Info("No existing records found in Database for Hashes in Recorded Future", "error", err)
		} else if err != nil {
			lg.Error("Failed to read cached hashes from database", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		} else {
			lg.Info("Existing records found in Database for Hashes in Recorded Future", "path", c.FullPath())
			existingData = append(existingData, data...)
			for _, record := range data {
				foundIOCs[record.IOC] = true
			}
		}
	}

	// Filter out IOCs that already exist in the database
	// Only make API calls for IOCs that haven't been looked up yet
	var newIPs, newDomains, newHashes []string

	for _, ip := range ips {
		if !foundIOCs[ip] {
			newIPs = append(newIPs, ip)
		}
	}

	for _, domain := range domains {
		if !foundIOCs[domain] {
			newDomains = append(newDomains, domain)
		}
	}

	for _, hash := range hashes {
		if !foundIOCs[hash] {
			newHashes = append(newHashes, hash)
		}
	}

	var enrichmentResults []models.IOCTable
	var responsePayloads []models.RecordSOARResponsePayload

	if len(newIPs) > 0 {
		for _, ip := range newIPs {
			iocType := models.IOCClassifier(ip)
			if iocType != "IPv4" && iocType != "IPv6" {
				lg.Error("Invalid IP address format", "ip", ip)
				responsePayloads = append(responsePayloads, models.RecordSOARResponsePayload{
					IOC:     ip,
					Score:   0,
					Success: false,
				})
				failureCount++
				continue
			}
			score, err := a.RecordedFuture.GetRecordedFutureEnrichment(c, ip, a.SSM, a.KMS, lg)
			if err != nil {
				lg.Error("Error calling Recorded Future API for IP", "ip", ip, "error", err)
				responsePayloads = append(responsePayloads, models.RecordSOARResponsePayload{
					IOC:     ip,
					Score:   0,
					Success: false,
				})
				failureCount++
				continue
			}
			confidenceLevel := models.GetMaliciousConfidenceLevel(score)
			loc, _ := time.LoadLocation("Australia/Sydney")
			record := models.IOCTable{
				IOC:                 ip,
				IncidentID:          incidentId,
				IOCType:             iocType,
				EnrichmentSource:    "RecordedFuture",
				MaliciousConfidence: string(confidenceLevel),
				Date:                time.Now().In(loc).Format("02-01-2006"),
				Info: map[string]interface{}{
					"Score": score,
				},
			}
			enrichmentResults = append(enrichmentResults, record)
			responsePayloads = append(responsePayloads, models.RecordSOARResponsePayload{
				IOC:     ip,
				Score:   score,
				Success: true,
			})
			successCount++
		}
	}

	if len(newDomains) > 0 {
		for _, domain := range newDomains {
			iocType := models.IOCClassifier(domain)
			if iocType != "Domain" {
				lg.Error("Invalid Domain format", "domain", domain)
				responsePayloads = append(responsePayloads, models.RecordSOARResponsePayload{
					IOC:     domain,
					Score:   0,
					Success: false,
				})
				failureCount++
				continue
			}
			score, err := a.RecordedFuture.GetRecordedFutureEnrichment(c, domain, a.SSM, a.KMS, lg)
			if err != nil {
				lg.Error("Error calling Recorded Future API for Domain", "domain", domain, "error", err)
				responsePayloads = append(responsePayloads, models.RecordSOARResponsePayload{
					IOC:     domain,
					Score:   0,
					Success: false,
				})
				failureCount++
				continue
			}
			confidenceLevel := models.GetMaliciousConfidenceLevel(score)
			loc, _ := time.LoadLocation("Australia/Sydney")
			record := models.IOCTable{
				IOC:                 domain,
				IncidentID:          incidentId,
				IOCType:             iocType,
				EnrichmentSource:    "RecordedFuture",
				MaliciousConfidence: string(confidenceLevel),
				Date:                time.Now().In(loc).Format("02-01-2006"),
				Info: map[string]interface{}{
					"Score": score,
				},
			}
			enrichmentResults = append(enrichmentResults, record)
			responsePayloads = append(responsePayloads, models.RecordSOARResponsePayload{
				IOC:     domain,
				Score:   score,
				Success: true,
			})
			successCount++
		}
	}

	if len(newHashes) > 0 {
		for _, hash := range newHashes {
			iocType := models.IOCClassifier(hash)
			if iocType != "SHA1" && iocType != "SHA256" && iocType != "MD5" {
				lg.Error("Invalid Hash format", "hash", hash)
				responsePayloads = append(responsePayloads, models.RecordSOARResponsePayload{
					IOC:     hash,
					Score:   0,
					Success: false,
				})
				failureCount++
				continue
			}
			score, err := a.RecordedFuture.GetRecordedFutureEnrichment(c, hash, a.SSM, a.KMS, lg)
			if err != nil {
				lg.Error("Error calling Recorded Future API for Hash", "hash", hash, "error", err)
				responsePayloads = append(responsePayloads, models.RecordSOARResponsePayload{
					IOC:     hash,
					Score:   0,
					Success: false,
				})
				failureCount++
				continue
			}
			loc, _ := time.LoadLocation("Australia/Sydney")
			confidenceLevel := models.GetMaliciousConfidenceLevel(score)
			record := models.IOCTable{
				IOC:                 hash,
				IncidentID:          incidentId,
				IOCType:             iocType,
				EnrichmentSource:    "RecordedFuture",
				MaliciousConfidence: string(confidenceLevel),
				Date:                time.Now().In(loc).Format("02-01-2006"),
				Info: map[string]interface{}{
					"Score": score,
				},
			}
			enrichmentResults = append(enrichmentResults, record)
			responsePayloads = append(responsePayloads, models.RecordSOARResponsePayload{
				IOC:     hash,
				Score:   score,
				Success: true,
			})
			successCount++
		}
	}

	// Write enrichment results to database
	if len(enrichmentResults) > 0 {
		err := database.PutItemsIOCFinder(c, a.Dynamo, lg, enrichmentResults)
		if err != nil {
			lg.Error("Failed to write enrichment to database", "error", err)
			failureCount += len(enrichmentResults)
			successCount -= len(enrichmentResults)
		}
	}

	// Add cached results to response
	for _, cached := range existingData {
		var score int
		if cached.Info != nil {
			if infoScore, ok := cached.Info["Score"]; ok {
				switch v := infoScore.(type) {
				case int:
					score = v
				case float64:
					score = int(v)
				}
			}
		}
		responsePayloads = append(responsePayloads, models.RecordSOARResponsePayload{
			IOC:     cached.IOC,
			Score:   score,
			Success: true,
		})
	}

	batchResponse := models.RecordSOARBatchResponsePayload{
		Results: responsePayloads,
		Summary: models.RecordSOARResponseSummary{
			Total:     len(ips) + len(domains) + len(hashes),
			Succeeded: successCount,
			Failed:    failureCount,
		},
	}

	// Use 200 for all success, 207 for partial failure
	if failureCount == 0 {
		c.JSON(http.StatusOK, batchResponse)
	} else {
		c.JSON(http.StatusMultiStatus, batchResponse)
	}
}
