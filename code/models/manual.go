package models

type ManualRequestPayload struct {
	IOC         string `json:"ioc" validate:"required"`
	IncidentID  string `json:"incident_id" validate:"required"`
	Action      string `json:"action" validate:"required"`
	Integration string `json:"integration" validate:"required"`
	TenantID    string `json:"tenant_id" validate:"required"`
}

type ManualResponsePayload struct {
	Added bool `json:"added"`
}
