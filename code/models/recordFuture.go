package models

type RecordSOARRequestPayload struct {
	IPs        []string `json:"ips" validate:"max=10"`
	Domains    []string `json:"domains" validate:"max=10"`
	Hashes     []string `json:"hashes" validate:"max=10"`
	IncidentID string   `json:"incident_id" validate:"required"`
}

type RecordSOARResponsePayload struct {
	Score   int    `json:"score"`
	IOC     string `json:"ioc"`
	Success bool   `json:"success"`
}

type RecordSOARResponseSummary struct {
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
}

type RecordSOARBatchResponsePayload struct {
	Results []RecordSOARResponsePayload `json:"results"`
	Summary RecordSOARResponseSummary   `json:"summary"`
}

// //////////////////////////////API Specific Models///////////////////////////
type RecordFutureAPICallSOAR struct {
	IP     []string `json:"ip"`
	Domain []string `json:"domain"`
	Hash   []string `json:"hash"`
}

type RecordedFutureResponse struct {
	Data   RecordedFutureData `json:"data"`
	Counts Counts             `json:"counts"`
}

type RecordedFutureData struct {
	Results []RiskResult `json:"results"`
}

type RiskResult struct {
	Risk Risk `json:"risk"`
}

type Risk struct {
	Score int     `json:"score"`
	Level float64 `json:"level"`
}

type Counts struct {
	Returned int `json:"returned"`
	Total    int `json:"total"`
}
