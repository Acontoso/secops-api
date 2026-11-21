package app

import (
	"log/slog"

	"github.com/Acontoso/soar-api/code/database"
	"github.com/Acontoso/soar-api/code/models"
	"github.com/gin-gonic/gin"
)

// saveSOARRecord persists a SOAR action without failing the request, matching
// the existing best-effort call sites.
func (a *App) saveSOARRecord(c *gin.Context, lg *slog.Logger, entry *models.SOARTable) {
	if err := database.PutItemSOAR(c, a.Dynamo, lg, entry); err != nil {
		lg.Error("failed to put item into dynamodb", "error", err)
	}
}

// saveIOCRecord persists an enrichment record without failing the request.
func (a *App) saveIOCRecord(c *gin.Context, lg *slog.Logger, entry *models.IOCTable) {
	if err := database.PutItemIOCFinder(c, a.Dynamo, lg, entry); err != nil {
		lg.Error("failed to put item into dynamodb", "error", err)
	}
}
