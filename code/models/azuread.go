package models

type AzureADCARequestPayload struct {
	IOC        string `json:"ioc" validate:"required"`
	IncidentID string `json:"incident_id" validate:"required"`
	TenantID   string `json:"tenant_id" validate:"required"`
	ListID     string `json:"list_id" validate:"required"`
	ListName   string `json:"list_name" validate:"required"`
}

type AzureADCAResponsePayload struct {
	Action   string    `json:"action"`
	IOC      string    `json:"ioc"`
	ListName string    `json:"list_name"`
	IPRanges []IPRange `json:"ipRanges"`
}

// IPRange represents a single IP range (IPv4 or IPv6)
type IPRange struct {
	OdataType   string `json:"@odata.type"`
	CIDRAddress string `json:"cidrAddress"`
}

// NamedLocation represents a conditional access named location from Microsoft Graph
type NamedLocation struct {
	OdataType               string    `json:"@odata.type"`
	ID                      string    `json:"id"`
	DisplayName             string    `json:"displayName"`
	CreatedDateTime         string    `json:"createdDateTime"`
	ModifiedDateTime        string    `json:"modifiedDateTime"`
	IsTrusted               bool      `json:"isTrusted"`
	IPRanges                []IPRange `json:"ipRanges"`
	CountriesAndRegions     []string  `json:"countriesAndRegions"`
	IncludeUnknownCountries bool      `json:"includeUnknownCountriesAndRegions"`
}

// NamedLocationsResponse represents the full response from Microsoft Graph
type NamedLocationsResponse struct {
	OdataContext string          `json:"@odata.context"`
	Value        []NamedLocation `json:"value"`
}

// IPRangesOnly extracts just the IP ranges from named locations
type IPRangesOnly struct {
	IPRanges []IPRange `json:"ipRanges"`
}

// CAGraphPayload - deprecated, use NamedLocation instead
type CAGraphPayload struct {
	DataType    string    `json:"@odata.type"`
	DisplayName string    `json:"displayName"`
	IsTrusted   bool      `json:"isTrusted"`
	IPRanges    []IPRange `json:"ipRanges"`
}

// IPRanges - deprecated, use IPRange instead
type IPRanges struct {
	OdataType string `json:"@odata.type"`
	Address   string `json:"cidrAddress"`
}
