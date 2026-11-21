package app

import (
	"errors"
	"log/slog"
	"time"

	"github.com/Acontoso/soar-api/code/database"
	"github.com/Acontoso/soar-api/code/models"
	"github.com/gin-gonic/gin"
)

// recordedFutureCategory describes one IOC list accepted by the endpoint.
type recordedFutureCategory struct {
	name       string
	lowerName  string
	logField   string
	items      []string
	isValid    func(string) bool
	invalidLog string
	errorLog   string
}

func (a *App) enrichRecordedFuture(c *gin.Context, payload models.RecordSOARRequestPayload, lg *slog.Logger) (models.RecordSOARBatchResponsePayload, error) {
	categories := []recordedFutureCategory{
		{
			name: "IPs", lowerName: "IPs", logField: "ip", items: payload.IPs,
			isValid:    func(t string) bool { return t == "IPv4" || t == "IPv6" },
			invalidLog: "Invalid IP address format",
			errorLog:   "Error calling Recorded Future API for IP",
		},
		{
			name: "Domains", lowerName: "domains", logField: "domain", items: payload.Domains,
			isValid:    func(t string) bool { return t == "Domain" },
			invalidLog: "Invalid Domain format",
			errorLog:   "Error calling Recorded Future API for Domain",
		},
		{
			name: "Hashes", lowerName: "hashes", logField: "hash", items: payload.Hashes,
			isValid:    func(t string) bool { return t == "SHA1" || t == "SHA256" || t == "MD5" },
			invalidLog: "Invalid Hash format",
			errorLog:   "Error calling Recorded Future API for Hash",
		},
	}

	var existing []models.IOCTable
	found := make(map[string]bool)
	for _, category := range categories {
		if len(category.items) == 0 {
			continue
		}
		records, err := a.cachedCategoryIOCs(c, category, lg)
		if err != nil {
			return models.RecordSOARBatchResponsePayload{}, err
		}
		existing = append(existing, records...)
		for _, record := range records {
			found[record.IOC] = true
		}
	}

	var records []models.IOCTable
	var results []models.RecordSOARResponsePayload
	succeeded, failed := 0, 0
	for _, category := range categories {
		batch := a.enrichRecordedFutureCategory(c, category, found, payload.IncidentID, lg)
		records = append(records, batch.records...)
		results = append(results, batch.results...)
		succeeded += batch.succeeded
		failed += batch.failed
	}

	if len(records) > 0 {
		if err := database.PutItemsIOCFinder(c, a.Dynamo, lg, records); err != nil {
			lg.Error("Failed to write enrichment to database", "error", err)
			failed += len(records)
			succeeded -= len(records)
		}
	}

	for _, cached := range existing {
		succeeded++
		results = append(results, models.RecordSOARResponsePayload{
			IOC:     cached.IOC,
			Score:   scoreFromInfo(cached.Info),
			Success: true,
		})
	}

	total := len(payload.IPs) + len(payload.Domains) + len(payload.Hashes)
	return models.RecordSOARBatchResponsePayload{
		Results: results,
		Summary: models.RecordSOARResponseSummary{Total: total, Succeeded: succeeded, Failed: failed},
	}, nil
}

func (a *App) cachedCategoryIOCs(c *gin.Context, category recordedFutureCategory, lg *slog.Logger) ([]models.IOCTable, error) {
	data, err := database.GetItemsIOCFinder(c, a.Dynamo, category.items, "RecordedFuture", lg)
	switch {
	case errors.Is(err, database.ErrNotFound):
		lg.Info("No existing records found in Database for "+category.name+" in Recorded Future", "error", err)
		return nil, nil
	case err != nil:
		lg.Error("Failed to read cached "+category.lowerName+" from database", "error", err)
		return nil, err
	default:
		lg.Info("Existing records found in Database for "+category.name+" in Recorded Future", "path", c.FullPath())
		return data, nil
	}
}

type recordedFutureEnrichment struct {
	records   []models.IOCTable
	results   []models.RecordSOARResponsePayload
	succeeded int
	failed    int
}

// enrichRecordedFutureCategory preserves input order and duplicate IOCs. Cache
// membership is shared across categories, but fresh results are not deduplicated.
func (a *App) enrichRecordedFutureCategory(c *gin.Context, category recordedFutureCategory, found map[string]bool, incidentID string, lg *slog.Logger) recordedFutureEnrichment {
	var batch recordedFutureEnrichment
	for _, ioc := range category.items {
		if found[ioc] {
			continue
		}
		iocType := models.IOCClassifier(ioc)
		if !category.isValid(iocType) {
			lg.Error(category.invalidLog, category.logField, ioc)
			batch.results = append(batch.results, models.RecordSOARResponsePayload{IOC: ioc, Success: false})
			batch.failed++
			continue
		}

		score, err := a.RecordedFuture.GetRecordedFutureEnrichment(c, ioc, a.SSM, a.KMS, lg)
		if err != nil {
			lg.Error(category.errorLog, category.logField, ioc, "error", err)
			batch.results = append(batch.results, models.RecordSOARResponsePayload{IOC: ioc, Success: false})
			batch.failed++
			continue
		}

		batch.records = append(batch.records, models.IOCTable{
			IOC:                 ioc,
			IncidentID:          incidentID,
			IOCType:             iocType,
			EnrichmentSource:    "RecordedFuture",
			MaliciousConfidence: string(models.GetMaliciousConfidenceLevel(score)),
			Date:                sydneyDate(time.Now()),
			Info:                map[string]interface{}{"Score": score},
		})
		batch.results = append(batch.results, models.RecordSOARResponsePayload{IOC: ioc, Score: score, Success: true})
		batch.succeeded++
	}
	return batch
}
