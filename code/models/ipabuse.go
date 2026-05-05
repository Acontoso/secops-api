package models

type ClientAbuseIPRequestPayload struct {
	IP         string `json:"ip" validate:"required"`
	IncidentID string `json:"incident_id" validate:"required"`
}

type ClientAbuseIPResponsePayload struct {
	Confidence           string `json:"confidence"`
	AbuseConfidenceScore int    `json:"abuse_confidence_score"`
	Country              string `json:"country"`
	ReportCount          int    `json:"report_count"`
	TOR                  bool   `json:"tor"`
	Private              bool   `json:"private"`
	IOC                  string `json:"ioc"`
	Exists               bool   `json:"exists,omitempty"`
}

// AbuseIPDBResponse models the subset of fields we care about.
type AbuseIPDBResponse struct {
	Data struct {
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryName          string `json:"countryName"`
		TotalReports         int    `json:"totalReports"`
		IsTor                bool   `json:"isTor"`
		CountryCode          string `json:"countryCode"`
		Usage                string `json:"usageType"`
	} `json:"data"`
}

type ManualLookupIPRequestPayload struct {
	IP string `json:"ip" validate:"required"`
}

type ManualAddAbuseIPPayload struct {
	IP                   string `json:"ip" validate:"required"`
	Public               bool   `json:"public" validate:"required"`
	AbuseConfidenceScore int    `json:"abuse_confidence_score" validate:"required"`
	Country              string `json:"country" validate:"required"`
	CountryCode          string `json:"country_code" validate:"required"`
	ReportCount          int    `json:"report_count" validate:"required"`
	IncidentID           string `json:"incident_id" validate:"required"`
}
