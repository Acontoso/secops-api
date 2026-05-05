package database

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/Acontoso/soar-api/code/models"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/gin-gonic/gin"
)

var IOC_TABLE_NAME string = os.Getenv("IOC_TABLE_NAME")
var IOC_TABLE_HASH_KEY string = os.Getenv("IOC_TABLE_HASH_KEY")
var IOC_TABLE_SORT_KEY string = os.Getenv("IOC_TABLE_SORT_KEY")

var SOAR_ACTIONS_TABLE_NAME string = os.Getenv("SOAR_ACTIONS_TABLE_NAME")
var SOAR_ACTIONS_TABLE_HASH_KEY string = os.Getenv("SOAR_ACTIONS_TABLE_HASH_KEY")
var SOAR_ACTIONS_SORT_KEY string = os.Getenv("SOAR_ACTIONS_SORT_KEY")

var (
	ErrNotFound   = errors.New("Item not found")
	ErrNoDBClient = errors.New("Dynamodb client missing")
)

// NewDynamoDBClient initializes and returns a DynamoDB client

func NewDynamoDBClient(ctx context.Context) (*dynamodb.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("ap-southeast-2"))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return dynamodb.NewFromConfig(cfg), nil
}

func getKeyIOC(ioc models.IOCTable) map[string]types.AttributeValue {
	IOC, err := attributevalue.Marshal(ioc.IOC)
	if err != nil {
		panic(err)
	}
	Source, err := attributevalue.Marshal(ioc.EnrichmentSource)
	if err != nil {
		panic(err)
	}
	return map[string]types.AttributeValue{"IOC": IOC, "EnrichmentSource": Source}
}

func getKeysIOC(ioc models.IOCTableBatch) []map[string]types.AttributeValue {
	keys := make([]map[string]types.AttributeValue, len(ioc.IOC))
	EnrichmentSource, err := attributevalue.Marshal(ioc.EnrichmentSource)
	if err != nil {
		panic(err)
	}
	for i, ioc := range ioc.IOC {
		keys[i] = map[string]types.AttributeValue{
			"IOC":              &types.AttributeValueMemberS{Value: ioc},
			"EnrichmentSource": EnrichmentSource,
		}
	}
	return keys
}

func GetItemIOCFinder(c *gin.Context, client *dynamodb.Client, hash_key_value string, sort_key_value string, lg *slog.Logger) (*models.IOCTable, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return nil, ErrNoDBClient
	}
	//pointer since it will let you return nil if item not present
	data := &models.IOCTable{
		IOC:              hash_key_value,
		EnrichmentSource: sort_key_value,
	}

	resp, err := client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &IOC_TABLE_NAME,
		Key:       getKeyIOC(*data),
	})
	if err != nil {
		lg.Error("Error pulling data from database", "error", err)
		return nil, err
	}

	if len(resp.Item) == 0 {
		return nil, ErrNotFound
	}

	if err := attributevalue.UnmarshalMap(resp.Item, data); err != nil {
		lg.Error("Couldn't unmarshal response", "error", err)
		return nil, err
	}
	lg.Info("Database hit for IOC", "IOC", data.IOC, "Source", data.EnrichmentSource)

	return data, nil
}

func GetItemsIOCFinder(c *gin.Context, client *dynamodb.Client, hash_key_values []string, sort_key_value string, lg *slog.Logger) ([]models.IOCTable, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return nil, ErrNoDBClient
	}
	//pointer since it will let you return nil if item not present
	data := &models.IOCTableBatch{
		IOC:              hash_key_values,
		EnrichmentSource: sort_key_value,
	}

	resp, err := client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
		RequestItems: map[string]types.KeysAndAttributes{
			IOC_TABLE_NAME: {
				Keys: getKeysIOC(*data),
			},
		},
	})
	if err != nil {
		lg.Error("Error pulling data from database", "error", err)
		return nil, err
	}

	if len(resp.Responses) == 0 {
		return nil, ErrNotFound
	}

	var results []models.IOCTable
	for _, item := range resp.Responses[IOC_TABLE_NAME] {
		var record models.IOCTable
		if err := attributevalue.UnmarshalMap(item, &record); err != nil {
			lg.Error("Couldn't unmarshal response", "error", err)
			continue
		}
		lg.Info("Database hit for IOC", "IOC", record.IOC, "Source", record.EnrichmentSource)
		results = append(results, record)
	}
	return results, nil
}

func PutItemIOCFinder(c *gin.Context, client *dynamodb.Client, lg *slog.Logger, data *models.IOCTable) error {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return ErrNoDBClient
	}

	item, err := attributevalue.MarshalMap(data)
	_, err = client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &IOC_TABLE_NAME,
		Item:      item,
	})
	if err != nil {
		lg.Error("Couldn't add item to table", "error", err)
	} else {
		lg.Info("Database record added for IOC", "IOC", data.IOC, "Source", data.EnrichmentSource)
	}
	return err
}

func PutItemsIOCFinder(c *gin.Context, client *dynamodb.Client, lg *slog.Logger, data []models.IOCTable) error {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return ErrNoDBClient
	}

	const batchSize = 25
	// PutItems function has a max batch size of 25, so we need to split our data into batches if we have more than 25 items to add. This loop handles that batching logic.
	for i := 0; i < len(data); i += batchSize {
		end := i + batchSize
		// If the end index exceeds the length of the data slice, we set it to the length of the data slice to avoid an out-of-range error.
		if end > len(data) {
			end = len(data)
		}
		// We then take a slice of the data for the current batch.
		batch := data[i:end]

		writeRequests := make([]types.WriteRequest, 0, len(batch))
		marshaledRecords := make([]models.IOCTable, 0, len(batch))
		for _, item := range batch {
			marshaledItem, err := attributevalue.MarshalMap(item)
			if err != nil {
				lg.Error("Failed to marshal item", "error", err)
				continue
			}
			writeRequests = append(writeRequests, types.WriteRequest{
				PutRequest: &types.PutRequest{
					Item: marshaledItem,
				},
			})
			marshaledRecords = append(marshaledRecords, item)
		}
		if len(writeRequests) == 0 {
			continue
		}

		resp, err := client.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
			RequestItems: map[string][]types.WriteRequest{
				IOC_TABLE_NAME: writeRequests,
			},
		})
		if err != nil {
			lg.Error("Couldn't batch write items", "error", err)
			return err
		}

		unprocessed := make(map[string]struct{})
		for _, request := range resp.UnprocessedItems[IOC_TABLE_NAME] {
			if request.PutRequest == nil {
				continue
			}
			iocAttr, iocOk := request.PutRequest.Item["IOC"].(*types.AttributeValueMemberS)
			sourceAttr, sourceOk := request.PutRequest.Item["EnrichmentSource"].(*types.AttributeValueMemberS)
			if !iocOk || !sourceOk {
				continue
			}
			unprocessed[iocAttr.Value+"|"+sourceAttr.Value] = struct{}{}
		}

		for _, item := range marshaledRecords {
			if _, exists := unprocessed[item.IOC+"|"+item.EnrichmentSource]; exists {
				continue
			}
			lg.Info("Database record added for IOC", "IOC", item.IOC, "Source", item.EnrichmentSource)
		}
	}

	return nil
}

func getKeySOAR(ioc models.SOARTable) map[string]types.AttributeValue {
	IOC, err := attributevalue.Marshal(ioc.IOC)
	if err != nil {
		panic(err)
	}
	Integration, err := attributevalue.Marshal(ioc.Integration)
	if err != nil {
		panic(err)
	}
	return map[string]types.AttributeValue{"IOC": IOC, "Integration": Integration}
}

func getKeysSOAR(ioc models.SOARTableBatch) []map[string]types.AttributeValue {
	keys := make([]map[string]types.AttributeValue, len(ioc.IOC))
	Integration, err := attributevalue.Marshal(ioc.Integration)
	if err != nil {
		panic(err)
	}
	for i, ioc := range ioc.IOC {
		keys[i] = map[string]types.AttributeValue{
			"IOC":         &types.AttributeValueMemberS{Value: ioc},
			"Integration": Integration,
		}
	}
	return keys
}

func GetItemSOAR(c *gin.Context, client *dynamodb.Client, hash_key_value string, sort_key_value string, lg *slog.Logger) (*models.SOARTable, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return nil, ErrNoDBClient
	}
	//pointer since it will let you return nil if item not present
	data := &models.SOARTable{
		IOC:         hash_key_value,
		Integration: sort_key_value,
	}

	resp, err := client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &SOAR_ACTIONS_TABLE_NAME,
		Key:       getKeySOAR(*data),
	})
	if err != nil {
		lg.Error("Error pulling data from database", "error", err)
		return nil, err
	}

	if len(resp.Item) == 0 {
		return nil, ErrNotFound
	}

	if err := attributevalue.UnmarshalMap(resp.Item, data); err != nil {
		lg.Error("Couldn't unmarshal response", "error", err)
		return nil, err
	}
	lg.Info("Database hit for IOC", "IOC", data.IOC, "Source", data.Integration)

	return data, nil
}

func PutItemSOAR(c *gin.Context, client *dynamodb.Client, lg *slog.Logger, data *models.SOARTable) error {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return ErrNoDBClient
	}

	item, err := attributevalue.MarshalMap(data)
	_, err = client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &SOAR_ACTIONS_TABLE_NAME,
		Item:      item,
	})
	if err != nil {
		lg.Error("Couldn't add item to table", "error", err)
	} else {
		lg.Info("Database record added for IOC", "IOC", data.IOC, "Integration", data.Integration)
	}
	return err
}

func GetItemsSOAR(c *gin.Context, client *dynamodb.Client, hash_key_values []string, sort_key_value string, lg *slog.Logger) ([]models.SOARTable, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return nil, ErrNoDBClient
	}
	//pointer since it will let you return nil if item not present
	data := &models.SOARTableBatch{
		IOC:         hash_key_values,
		Integration: sort_key_value,
	}

	resp, err := client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
		RequestItems: map[string]types.KeysAndAttributes{
			SOAR_ACTIONS_TABLE_NAME: {
				Keys: getKeysSOAR(*data),
			},
		},
	})
	if err != nil {
		lg.Error("Error pulling data from database", "error", err)
		return nil, err
	}

	if len(resp.Responses) == 0 {
		return nil, ErrNotFound
	}

	var results []models.SOARTable
	for _, item := range resp.Responses[SOAR_ACTIONS_TABLE_NAME] {
		var record models.SOARTable
		if err := attributevalue.UnmarshalMap(item, &record); err != nil {
			lg.Error("Couldn't unmarshal response", "error", err)
			continue
		}
		lg.Info("Database hit for IOC", "IOC", record.IOC, "Integration", record.Integration)
		results = append(results, record)
	}

	return results, nil
}

func PutItemsSOAR(c *gin.Context, client *dynamodb.Client, lg *slog.Logger, data []models.SOARTable) error {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return ErrNoDBClient
	}

	const batchSize = 25

	for i := 0; i < len(data); i += batchSize {
		end := i + batchSize
		if end > len(data) {
			end = len(data)
		}
		batch := data[i:end]

		writeRequests := make([]types.WriteRequest, 0, len(batch))
		marshaledRecords := make([]models.SOARTable, 0, len(batch))
		for _, item := range batch {
			marshaledItem, err := attributevalue.MarshalMap(item)
			if err != nil {
				lg.Error("Failed to marshal item", "error", err)
				continue
			}
			writeRequests = append(writeRequests, types.WriteRequest{
				PutRequest: &types.PutRequest{
					Item: marshaledItem,
				},
			})
			marshaledRecords = append(marshaledRecords, item)
		}

		if len(writeRequests) == 0 {
			continue
		}

		resp, err := client.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
			RequestItems: map[string][]types.WriteRequest{
				SOAR_ACTIONS_TABLE_NAME: writeRequests,
			},
		})
		if err != nil {
			lg.Error("Couldn't batch write items", "error", err)
			return err
		}

		unprocessed := make(map[string]struct{})
		for _, request := range resp.UnprocessedItems[SOAR_ACTIONS_TABLE_NAME] {
			if request.PutRequest == nil {
				continue
			}
			iocAttr, iocOk := request.PutRequest.Item["IOC"].(*types.AttributeValueMemberS)
			integrationAttr, integrationOk := request.PutRequest.Item["Integration"].(*types.AttributeValueMemberS)
			if !iocOk || !integrationOk {
				continue
			}
			unprocessed[iocAttr.Value+"|"+integrationAttr.Value] = struct{}{}
		}

		for _, item := range marshaledRecords {
			if _, exists := unprocessed[item.IOC+"|"+item.Integration]; exists {
				continue
			}
			lg.Info("Database record added for IOC", "IOC", item.IOC, "Integration", item.Integration)
		}
	}

	return nil
}

func UpdateItemSOARAccounts(c *gin.Context, client *dynamodb.Client, lg *slog.Logger, ioc string, integration string, account string) error {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return ErrNoDBClient
	}

	key := map[string]types.AttributeValue{
		"IOC":         &types.AttributeValueMemberS{Value: ioc},
		"Integration": &types.AttributeValueMemberS{Value: integration},
	}
	// The ":" are placeholder values that are replaced during the update. This allows us to append to the Accounts list without needing to know its current value, and also handles the case where Accounts doesn't exist yet (using if_not_exists).
	updateExpression := "SET Info.Accounts = list_append(if_not_exists(Info.Accounts, :empty_list), :new_account)"

	_, err := client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        &SOAR_ACTIONS_TABLE_NAME,
		Key:              key,
		UpdateExpression: &updateExpression,
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":new_account": &types.AttributeValueMemberL{
				Value: []types.AttributeValue{
					&types.AttributeValueMemberS{Value: account},
				},
			},
			":empty_list": &types.AttributeValueMemberL{Value: []types.AttributeValue{}},
		},
	})

	if err != nil {
		lg.Error("Couldn't update item", "error", err)
		return err
	}
	lg.Info("Database record updated for SOAR action", "Account Added", account)
	return nil
}
