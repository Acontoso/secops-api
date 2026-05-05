package models

type IOCTable struct {
	IOC                 string                 `dynamodbav:"IOC"`
	EnrichmentSource    string                 `dynamodbav:"EnrichmentSource"`
	IOCType             string                 `dynamodbav:"IOCType"`
	IncidentID          string                 `dynamodbav:"IncidentID"`
	MaliciousConfidence string                 `dynamodbav:"MaliciousConfidence"`
	Date                string                 `dynamodbav:"Date"`
	Info                map[string]interface{} `dynamodbav:"Info"`
}

type SOARTable struct {
	IOC         string                 `dynamodbav:"IOC"`
	Integration string                 `dynamodbav:"Integration"`
	Date        string                 `dynamodbav:"Date"`
	IncidentID  string                 `dynamodbav:"IncidentID"`
	Info        map[string]interface{} `dynamodbav:"Info"`
}

type IOCTableBatch struct {
	IOC                 []string               `dynamodbav:"IOC"`
	EnrichmentSource    string                 `dynamodbav:"EnrichmentSource"`
	IOCType             string                 `dynamodbav:"IOCType"`
	IncidentID          string                 `dynamodbav:"IncidentID"`
	MaliciousConfidence string                 `dynamodbav:"MaliciousConfidence"`
	Date                string                 `dynamodbav:"Date"`
	Info                map[string]interface{} `dynamodbav:"Info"`
}

type SOARTableBatch struct {
	IOC         []string               `dynamodbav:"IOC"`
	Integration string                 `dynamodbav:"Integration"`
	Date        string                 `dynamodbav:"Date"`
	IncidentID  string                 `dynamodbav:"IncidentID"`
	Info        map[string]interface{} `dynamodbav:"Info"`
}
