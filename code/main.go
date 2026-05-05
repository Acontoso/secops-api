package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	appcontainer "github.com/Acontoso/soar-api/code/app"
	"github.com/Acontoso/soar-api/code/database"
	"github.com/Acontoso/soar-api/code/middleware"
	"github.com/Acontoso/soar-api/code/routes"
	"github.com/Acontoso/soar-api/code/services"
	"github.com/aws/aws-lambda-go/lambda"
	ginadapter "github.com/awslabs/aws-lambda-go-api-proxy/gin"
	"github.com/gin-gonic/gin"
)

var ginLambda *ginadapter.GinLambda

func main() {
	// Gin makes a goroutine per request, so doesnt block or slow other requests
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// initialize DynamoDB client once
	// Context here is background since we want the client to outlive any single request
	dynamoClient, err := database.NewDynamoDBClient(context.Background())
	if err != nil {
		slog.Error("failed to initialize dynamodb client", "error", err)
		return
	}
	kmsClient, err := services.NewKMSClient(context.Background())
	if err != nil {
		slog.Error("failed to initialize kms client", "error", err)
		return
	}
	ssmClient, err := services.NewSSMClient(context.Background())
	if err != nil {
		slog.Error("failed to initialize ssm client", "error", err)
		return
	}

	cognitoClient, err := services.NewCognitoClient(context.Background())
	if err != nil {
		slog.Error("failed to initialize cognito client", "error", err)
		return
	}

	abuseClient := services.NewAbuseIPDBClient()
	anomaliClient := services.NewAnomaliClient()
	zscalerClient := services.NewZscalerClient()
	recordedFutureClient := services.NewFutureClient()

	app := &appcontainer.App{
		Router:         gin.New(),
		Dynamo:         dynamoClient,
		KMS:            kmsClient,
		SSM:            ssmClient,
		Cognito:        cognitoClient,
		AbuseIPDB:      abuseClient,
		Anomali:        anomaliClient,
		Zscaler:        zscalerClient,
		RecordedFuture: recordedFutureClient,
	}

	app.Router.Use(middleware.JSONLogger(), gin.Recovery())
	app.Router.GET("/", func(c *gin.Context) {
		c.String(200, "API is healthy!")
	})
	app.Router.GET("/health", func(c *gin.Context) {
		c.String(200, "API is healthy!")
	})

	// Pass app to route setup
	routes.SetupProtectedRoutes(app)

	slog.Info("API application is starting... and successfully initialized")

	// Check if running in Lambda
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		slog.Info("Running in AWS Lambda")
		ginLambda = ginadapter.New(app.Router)
		lambda.Start(ginLambda.ProxyWithContext)
	} else {
		slog.Info("Running locally on :8080")
		if err := app.Router.Run(":8080"); err != nil {
			fmt.Println("Failed to start server", err)
		}
	}
}
