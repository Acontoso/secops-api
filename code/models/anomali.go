package models

type AnomaliRequestPayload struct {
	IOC        string `json:"ioc" validate:"required"`
	IncidentID string `json:"incident_id" validate:"required"`
}

type AnomaliResponsePayload struct {
	Confidence string `json:"confidence"`
	IOCType    string `json:"ioc_type"`
	IOC        string `json:"ioc"`
	Score      int    `json:"score"`
}
