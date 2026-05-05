package models

type Action string

const (
	Block             Action = "Block"
	Audit             Action = "Audit"
	BlockAndRemediate Action = "BlockAndRemediate"
)

type DATPUploadRequestPayload struct {
	IOC        string `json:"ioc" validate:"required"`
	IncidentID string `json:"incident_id" validate:"required"`
	Action     Action `json:"action" validate:"required"`
	TenantID   string `json:"tenant_id" validate:"required"`
}

type DATPUploadResponsePayload struct {
	Added    bool   `json:"added"`
	IOC      string `json:"ioc"`
	Platform string `json:"platform"`
	Action   Action `json:"action"`
}

type DATPUpdatePayload struct {
	IndicatorValue string `json:"indicatorValue"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Action         Action `json:"action"`
	Severity       string `json:"severity"`
	IndicatorType  string `json:"indicatorType"`
	GenerateAlert  bool   `json:"generateAlert"`
	ExpirationTime string `json:"expirationTime"`
}
