package models

type SSEUploadRequestPayload struct {
	IOCs       []string `json:"iocs" validate:"required,min=1,max=10"`
	IncidentID string   `json:"incident_id" validate:"required"`
}

type SSEUploadResponsePayload struct {
	Added       bool   `json:"added"`
	IOC         string `json:"ioc"`
	Integration string `json:"integration"`
	Action      string `json:"action"`
}

type ZscalerAddPayload struct {
	Addresses []string `json:"addresses"`
	Type      string   `json:"type,omitempty"`
	Name      string   `json:"name,omitempty"`
}

type SSEUploadSummary struct {
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
}

type SSEUploadBatchResponsePayload struct {
	Results []SSEUploadResponsePayload `json:"results"`
	Summary SSEUploadSummary           `json:"summary"`
}
