package middleware

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var COGNITOID string = "ap-southeast-2_jL1tizlq8"
var CLIENTID string = "62l32mjlofb4r3l4po18h9f5bg"

func getJWKS(cognitoUserPoolId string) (keyfunc.Keyfunc, error) {

	jwksURL := fmt.Sprintf("https://cognito-idp.ap-southeast-2.amazonaws.com/%s/.well-known/jwks.json", cognitoUserPoolId)

	jwks, err := keyfunc.NewDefault([]string{jwksURL})
	if err != nil {
		log.Fatalf("Failed to create JWK Set from resource at the given URL.\nError: %s", err)
	}
	return jwks, nil
}

func CognitoAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		// Retrieve JWT from the "Authorization" header
		authHeader := c.GetHeader("Authorization")
		splitToken := strings.Split(authHeader, "Bearer ")

		if len(splitToken) != 2 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		tokenString := splitToken[1]

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}
		jwks, err := getJWKS(COGNITOID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString,
			jwks.Keyfunc,
			jwt.WithValidMethods([]string{"RS256"}),
			jwt.WithExpirationRequired(),
			jwt.WithIssuer(fmt.Sprintf("https://cognito-idp.ap-southeast-2.amazonaws.com/%s", COGNITOID)))
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// Attempt to parse the JWT claims, properties of JWT tokens into a map of strings to interface{}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unable to parse claims"})
			// Abort prevents pending handlers from being called, wont stop current handler
			c.Abort()
			return
		}

		// Compare the "exp" claim to the current time
		expClaim, err := claims.GetExpirationTime()
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unable to get expiration time from JWT token"})
			c.Abort()
			return
		}
		if expClaim.Unix() < time.Now().Unix() {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has expired"})
			c.Abort()
			return
		}

		// "sub" claim exists in both ID and Access tokens
		subClaim, err := claims.GetSubject()
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}
		if subClaim != CLIENTID {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}
		c.Set("username", subClaim)
		// Get existing logger (with request_id) and add user_id to it
		reqLogger := GetLogger(c).With(slog.String("user_id", subClaim))
		c.Set("logger", reqLogger)
		c.Next()
	}
}
