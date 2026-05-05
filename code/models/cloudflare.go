package models

type CFAction string

const (
	BlockCF CFAction = "Block"
)

type CloudflareBlockIPRequestPayload struct {
	IPs          []string `json:"ips" validate:"required,min=1,max=10"`
	IncidentID   string   `json:"incident_id" validate:"required"`
	Action       CFAction `json:"action" validate:"required"`
	AccountNames []string `json:"account_names" validate:"required"`
}

type CloudflareBlockIPResponsePayload struct {
	Added   bool     `json:"added"`
	IOC     string   `json:"ioc"`
	Account string   `json:"accounts"`
	Action  CFAction `json:"action"`
}

type CloudflareBlockIPSummary struct {
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
}

type CloudflareBlockIPBatchResponsePayload struct {
	Results []CloudflareBlockIPResponsePayload `json:"results"`
	Summary CloudflareBlockIPSummary           `json:"summary"`
}
