package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	// Configure slog to use JSON handler so structured fields appear in CloudWatch
	// The init function gets called when the package is imported, setting up the logger for the entire application
	jsonHandler := slog.NewJSONHandler(os.Stdout, nil)
	slog.SetDefault(slog.New(jsonHandler))
}

type RequestlogEntry struct {
	Time      string  `json:"time"`
	RequestID string  `json:"request_id,omitempty"`
	ClientIP  string  `json:"client_ip"`
	Method    string  `json:"method"`
	Path      string  `json:"path"`
	Status    int     `json:"status"`
	LatencyMS float64 `json:"latency_ms"`
	Size      int     `json:"size_bytes"`
	UserAgent string  `json:"user_agent"`
	Error     string  `json:"error,omitempty"`
	Client    string  `json:"user_id,omitempty"`
}

// JSONLogger returns a Gin middleware that logs each request as a single JSON line to stdout.
func JSONLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		// generate a request id and attach to context so other handlers can use it
		reqID := newRequestID()
		reqLogger := slog.Default().With(slog.String("request_id", reqID))
		c.Set("logger", reqLogger)
		c.Set("request_id", reqID)
		// process request
		// Let Gin continue processing the request (handlers, other middleware).
		// Execution resumes here after the response is produced.
		// Awaits until request is processed and about to process response
		c.Next()

		stop := time.Now()
		latency := stop.Sub(start)

		path := c.Request.URL.Path
		if c.Request.URL.RawQuery != "" {
			path = path + "?" + c.Request.URL.RawQuery
		}
		username := c.GetString("username")

		entry := RequestlogEntry{
			Time:      start.Format(time.RFC3339Nano),
			RequestID: reqID,
			ClientIP:  c.RemoteIP(),
			Method:    c.Request.Method,
			Path:      path,
			Status:    c.Writer.Status(),
			LatencyMS: float64(latency.Nanoseconds()) / 1e6,
			Size:      c.Writer.Size(),
			UserAgent: c.Request.UserAgent(),
			Error:     c.Errors.ByType(gin.ErrorTypePrivate).String(),
			Client:    username,
		}

		b, err := json.Marshal(entry)
		if err != nil {
			// fallback to plain print on marshal error
			os.Stdout.WriteString("{\"time\":\"error marshaling log entry\"}\n")
			return
		}
		// Add newline for readability in stdout
		b = append(b, '\n')
		// Write to stdout (AWS will collect this and send to CloudWatch)
		_, _ = os.Stdout.Write(b)
	}
}

func newRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return time.Now().Format("20060102T150405.000000000")
	}
	return hex.EncodeToString(b)
}

// GetLogger returns the request-scoped logger stored in the Gin context
// or the default logger when none is present.
func GetLogger(c *gin.Context) *slog.Logger {
	if v, ok := c.Get("logger"); ok {
		if lg, ok2 := v.(*slog.Logger); ok2 {
			return lg
		}
	}
	return slog.Default()
}
