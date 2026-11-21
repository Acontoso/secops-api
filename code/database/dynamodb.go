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

	// errNilData guards the pointer-taking put operations against callers that
	// pass a nil record. Without it a successful PutItem would panic while
	// logging data.IOC.
	errNilData = errors.New("Dynamodb item data is nil")
	// errIncompleteBatch marks batch operations that did not fully succeed
	// (skipped items, unprocessed keys, or unprocessed writes). Results written
	// or read before the failure are still returned to the caller.
	errIncompleteBatch = errors.New("incomplete batch operation")
)

// NewDynamoDBClient initializes and returns a DynamoDB client

func NewDynamoDBClient(ctx context.Context) (*dynamodb.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
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

func GetItemIOCFinder(c *gin.Context, client *dynamodb.Client, hashKeyValue string, sortKeyValue string, lg *slog.Logger) (*models.IOCTable, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return nil, ErrNoDBClient
	}
	//pointer since it will let you return nil if item not present
	data := &models.IOCTable{
		IOC:              hashKeyValue,
		EnrichmentSource: sortKeyValue,
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

// batchGetSize is DynamoDB BatchGetItem's per-request key limit.
const batchGetSize = 100

// batchGetItems reads up to batchGetSize keys per BatchGetItem call. Duplicate
// input keys are collapsed (DynamoDB rejects duplicate keys), partial results
// survive a later-chunk failure, unprocessed keys are reported as errors, and a
// request that yields no records returns ErrNotFound.
func batchGetItems[T any](
	ctx context.Context,
	client *dynamodb.Client,
	lg *slog.Logger,
	tableName string,
	secondaryKey string,
	logKey string,
	hashKeyValues []string,
	secondaryValue string,
	logFields func(T) (ioc string, secondary string),
) ([]T, error) {
	// Deduplicate while preserving first-seen order.
	unique := make([]string, 0, len(hashKeyValues))
	seen := make(map[string]struct{}, len(hashKeyValues))
	for _, hashKey := range hashKeyValues {
		if _, exists := seen[hashKey]; exists {
			continue
		}
		seen[hashKey] = struct{}{}
		unique = append(unique, hashKey)
	}

	var results []T
	var decodeErr error
	for start := 0; start < len(unique); start += batchGetSize {
		end := start + batchGetSize
		if end > len(unique) {
			end = len(unique)
		}

		keys := make([]map[string]types.AttributeValue, 0, end-start)
		for _, hashKey := range unique[start:end] {
			keys = append(keys, map[string]types.AttributeValue{
				"IOC":        &types.AttributeValueMemberS{Value: hashKey},
				secondaryKey: &types.AttributeValueMemberS{Value: secondaryValue},
			})
		}

		resp, err := client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
			RequestItems: map[string]types.KeysAndAttributes{
				tableName: {Keys: keys},
			},
		})
		if err != nil {
			lg.Error("Error pulling data from database", "error", err)
			return results, err
		}

		for _, item := range resp.Responses[tableName] {
			var record T
			if err := attributevalue.UnmarshalMap(item, &record); err != nil {
				lg.Error("Couldn't unmarshal response", "error", err)
				decodeErr = errors.Join(decodeErr, err)
				continue
			}
			ioc, secondary := logFields(record)
			lg.Info("Database hit for IOC", "IOC", ioc, logKey, secondary)
			results = append(results, record)
		}

		if unprocessed := resp.UnprocessedKeys[tableName]; len(unprocessed.Keys) > 0 {
			lg.Error("Batch get returned unprocessed keys", "count", len(unprocessed.Keys))
			return results, fmt.Errorf("%w: %d unprocessed keys for table %s", errIncompleteBatch, len(unprocessed.Keys), tableName)
		}
	}

	if decodeErr != nil {
		return results, decodeErr
	}
	if len(results) == 0 {
		return nil, ErrNotFound
	}
	return results, nil
}

func GetItemsIOCFinder(c *gin.Context, client *dynamodb.Client, hashKeyValues []string, sortKeyValue string, lg *slog.Logger) ([]models.IOCTable, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return nil, ErrNoDBClient
	}

	return batchGetItems(ctx, client, lg, IOC_TABLE_NAME, "EnrichmentSource", "Source", hashKeyValues, sortKeyValue, func(item models.IOCTable) (string, string) {
		return item.IOC, item.EnrichmentSource
	})
}

func PutItemIOCFinder(c *gin.Context, client *dynamodb.Client, lg *slog.Logger, data *models.IOCTable) error {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return ErrNoDBClient
	}
	if data == nil {
		lg.Error("dynamodb item data is nil")
		return errNilData
	}

	item, err := attributevalue.MarshalMap(data)
	if err != nil {
		lg.Error("Couldn't marshal item", "error", err)
		return err
	}
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

const batchWriteSize = 25

// putItemsInBatches writes data using BatchWriteItem's 25-item limit. Marshaling
// failures and UnprocessedItems are logged; valid items are still written, but
// any skipped or unprocessed item makes the operation return errIncompleteBatch.
// An SDK error stops further batches immediately and is joined with any partial
// failures seen so far. There is deliberately no retry loop.
func putItemsInBatches[T any](
	ctx context.Context,
	client *dynamodb.Client,
	lg *slog.Logger,
	tableName string,
	data []T,
	secondaryKey string,
	logKey string,
	itemKeys func(T) (ioc string, secondary string),
) error {
	skipped := 0
	unprocessedCount := 0

	partialError := func() error {
		if skipped == 0 && unprocessedCount == 0 {
			return nil
		}
		if skipped == 0 {
			return fmt.Errorf("%w: %d unprocessed items", errIncompleteBatch, unprocessedCount)
		}
		if unprocessedCount == 0 {
			return fmt.Errorf("%w: %d items skipped after marshal failure", errIncompleteBatch, skipped)
		}
		return fmt.Errorf("%w: %d items skipped after marshal failure, %d unprocessed items", errIncompleteBatch, skipped, unprocessedCount)
	}

	for i := 0; i < len(data); i += batchWriteSize {
		end := i + batchWriteSize
		if end > len(data) {
			end = len(data)
		}
		batch := data[i:end]

		writeRequests := make([]types.WriteRequest, 0, len(batch))
		marshaledRecords := make([]T, 0, len(batch))
		for _, item := range batch {
			marshaledItem, err := attributevalue.MarshalMap(item)
			if err != nil {
				lg.Error("Failed to marshal item", "error", err)
				skipped++
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
				tableName: writeRequests,
			},
		})
		if err != nil {
			lg.Error("Couldn't batch write items", "error", err)
			return errors.Join(partialError(), err)
		}

		unprocessed := make(map[string]struct{})
		unprocessedResponses := resp.UnprocessedItems[tableName]
		if len(unprocessedResponses) > 0 {
			unprocessedCount += len(unprocessedResponses)
			lg.Error("Batch write returned unprocessed items", "count", len(unprocessedResponses))
		}
		for _, request := range unprocessedResponses {
			if request.PutRequest == nil {
				continue
			}
			iocAttr, iocOk := request.PutRequest.Item["IOC"].(*types.AttributeValueMemberS)
			secondaryAttr, secondaryOk := request.PutRequest.Item[secondaryKey].(*types.AttributeValueMemberS)
			if !iocOk || !secondaryOk {
				continue
			}
			unprocessed[iocAttr.Value+"|"+secondaryAttr.Value] = struct{}{}
		}

		for _, item := range marshaledRecords {
			ioc, secondary := itemKeys(item)
			if _, exists := unprocessed[ioc+"|"+secondary]; exists {
				continue
			}
			lg.Info("Database record added for IOC", "IOC", ioc, logKey, secondary)
		}
	}

	return partialError()
}

func PutItemsIOCFinder(c *gin.Context, client *dynamodb.Client, lg *slog.Logger, data []models.IOCTable) error {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return ErrNoDBClient
	}

	return putItemsInBatches(ctx, client, lg, IOC_TABLE_NAME, data, "EnrichmentSource", "Source", func(item models.IOCTable) (string, string) {
		return item.IOC, item.EnrichmentSource
	})
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

func GetItemSOAR(c *gin.Context, client *dynamodb.Client, hashKeyValue string, sortKeyValue string, lg *slog.Logger) (*models.SOARTable, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return nil, ErrNoDBClient
	}
	//pointer since it will let you return nil if item not present
	data := &models.SOARTable{
		IOC:         hashKeyValue,
		Integration: sortKeyValue,
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
	if data == nil {
		lg.Error("dynamodb item data is nil")
		return errNilData
	}

	item, err := attributevalue.MarshalMap(data)
	if err != nil {
		lg.Error("Couldn't marshal item", "error", err)
		return err
	}
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

func GetItemsSOAR(c *gin.Context, client *dynamodb.Client, hashKeyValues []string, sortKeyValue string, lg *slog.Logger) ([]models.SOARTable, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return nil, ErrNoDBClient
	}

	return batchGetItems(ctx, client, lg, SOAR_ACTIONS_TABLE_NAME, "Integration", "Integration", hashKeyValues, sortKeyValue, func(item models.SOARTable) (string, string) {
		return item.IOC, item.Integration
	})
}

func PutItemsSOAR(c *gin.Context, client *dynamodb.Client, lg *slog.Logger, data []models.SOARTable) error {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return ErrNoDBClient
	}

	return putItemsInBatches(ctx, client, lg, SOAR_ACTIONS_TABLE_NAME, data, "Integration", "Integration", func(item models.SOARTable) (string, string) {
		return item.IOC, item.Integration
	})
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
