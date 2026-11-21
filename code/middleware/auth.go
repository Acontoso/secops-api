package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/Acontoso/soar-api/code/config"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type jwksLoader func(string) (keyfunc.Keyfunc, error)

func getJWKS(issuer string) (keyfunc.Keyfunc, error) {
	// The cached production key set lives for the application lifetime.
	return loadJWKS(context.Background(), issuer, nil)
}

// loadJWKS allows an owner to cancel refresh workers and supply an offline HTTP
// client without changing any process-wide transport or factory.
func loadJWKS(ctx context.Context, issuer string, client *http.Client) (keyfunc.Keyfunc, error) {
	urls := []string{issuer + "/.well-known/jwks.json"}
	if client != nil {
		return keyfunc.NewDefaultOverrideCtx(ctx, urls, keyfunc.Override{Client: client})
	}
	return keyfunc.NewDefaultCtx(ctx, urls)
}

// bearerToken follows the Bearer grammar: a case-insensitive scheme, one or
// more ASCII spaces, then a nonempty token without surrounding whitespace.
func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimLeft(token, " ")
	if token == "" || strings.ContainsAny(token, " \t\r\n\v\f") {
		return "", false
	}
	return token, true
}

func CognitoAuthMiddleware() gin.HandlerFunc {
	cfg, err := config.LoadCognito(context.Background())
	if err != nil {
		slog.Error("Cognito authorization configuration is invalid", "error", err)
		return func(c *gin.Context) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		}
	}
	return cognitoAuthMiddleware(cfg, getJWKS)
}

func cognitoAuthMiddleware(cfg config.Cognito, load jwksLoader) gin.HandlerFunc {
	// Reuse the refreshing key set instead of spawning a refresh loop per request.
	// Failed initialization is retried, not made fatal or cached forever.
	var mu sync.Mutex
	var jwks keyfunc.Keyfunc
	return func(c *gin.Context) {
		unauthorized := func() {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		}
		tokenString, ok := bearerToken(c.GetHeader("Authorization"))
		if !ok {
			unauthorized()
			return
		}
		mu.Lock()
		if jwks == nil {
			var err error
			jwks, err = load(cfg.Issuer)
			if err != nil {
				mu.Unlock()
				unauthorized()
				return
			}
		}
		keys := jwks
		mu.Unlock()

		token, err := jwt.Parse(tokenString, keys.Keyfunc,
			jwt.WithValidMethods([]string{"RS256"}),
			jwt.WithExpirationRequired(), jwt.WithIssuer(cfg.Issuer))
		if err != nil || !token.Valid {
			unauthorized()
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || claims["token_use"] != "access" || claims["client_id"] != cfg.ClientID {
			unauthorized()
			return
		}
		scope, _ := claims["scope"].(string)
		hasScope := false
		for _, value := range strings.Fields(scope) {
			if value == cfg.RequiredScope {
				hasScope = true
				break
			}
		}
		if !hasScope {
			unauthorized()
			return
		}
		// Subject identifies the caller for logging only, never the app client.
		subject, _ := claims.GetSubject()
		c.Set("username", subject)
		c.Set("logger", GetLogger(c).With(slog.String("user_id", subject)))
		c.Next()
	}
}
