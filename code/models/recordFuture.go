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

// type Context struct {
// 	Phishing RiskCategory `json:"phishing"`
// 	Malware  RiskCategory `json:"malware"`
// 	Public   RiskCategory `json:"public"`
// 	C2       RiskCategory `json:"c2"`
// }

// type RiskCategory struct {
// 	Summary          []Summary `json:"summary"`
// 	Score            float64   `json:"score"`
// 	MostCriticalRule string    `json:"mostCriticalRule"`
// 	Rule             Rule      `json:"rule"`
// }

// type Summary struct {
// 	Level float64 `json:"level"`
// 	Count float64 `json:"count"`
// }

// type Rule struct {
// 	MaxCount int `json:"maxCount"`
// }

// type RuleInfo struct {
// 	Count        int                 `json:"count"`
// 	MostCritical string              `json:"mostCritical"`
// 	MaxCount     int                 `json:"maxCount"`
// 	Evidence     map[string]Evidence `json:"evidence"`
// 	Summary      []Summary           `json:"summary"`
// }

// type Evidence struct {
// 	Count       int     `json:"count"`
// 	Timestamp   string  `json:"timestamp"`
// 	Description string  `json:"description"`
// 	Rule        string  `json:"rule"`
// 	Sightings   int     `json:"sightings"`
// 	Mitigation  string  `json:"mitigation"`
// 	Level       float64 `json:"level"`
// }

// type Entity struct {
// 	ID   string `json:"id"`
// 	Name string `json:"name"`
// 	Type string `json:"type"`
// }

type Counts struct {
	Returned int `json:"returned"`
	Total    int `json:"total"`
}
