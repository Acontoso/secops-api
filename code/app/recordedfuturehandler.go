package app

import (
	"context"
	"net/http"
	"time"

	"github.com/Acontoso/soar-api/code/middleware"
	"github.com/Acontoso/soar-api/code/models"
	"github.com/gin-gonic/gin"
)

func (a *App) RecordedFutureSOAR(c *gin.Context) {
	_, cancel := context.WithTimeout(c, 100*time.Second)
	defer cancel()
	var payload models.RecordSOARRequestPayload
	lg := middleware.GetLogger(c)
	lg.Info("Recorded Future SOAR endpoint hit", "path", c.FullPath())
	if err := strictBindJSON(c, &payload); err != nil {
		respondBindError(c, lg, err)
		return
	}
	if err := validate.Struct(payload); err != nil {
		lg.Error("Validation of Recorded Future SOAR payload failed", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Validation of Recorded Future SOAR payload failed"})
		return
	}

	response, err := a.enrichRecordedFuture(c, payload, lg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	status := http.StatusOK
	if response.Summary.Failed != 0 {
		status = http.StatusMultiStatus
	}
	c.JSON(status, response)
}
