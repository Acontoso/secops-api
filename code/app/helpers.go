package app

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// respondBindError is the shared malformed-payload contract of the SOAR and
// enrichment endpoints.
func respondBindError(c *gin.Context, lg *slog.Logger, err error) {
	lg.Error("Error, failed to deserialise into JSON", "error", err)
	c.JSON(http.StatusBadRequest, gin.H{"Error": "Payload failed to deserialise into JSON"})
}

// sydneyDate formats a record date in the timezone used by existing records.
func sydneyDate(at time.Time) string {
	loc, _ := time.LoadLocation("Australia/Sydney")
	return at.In(loc).Format("02-01-2006")
}

// scoreFromInfo handles the numeric types used by live and cached enrichment data.
func scoreFromInfo(info map[string]interface{}) int {
	switch score := info["Score"].(type) {
	case int:
		return score
	case float64:
		return int(score)
	default:
		return 0
	}
}
