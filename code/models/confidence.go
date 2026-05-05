package models

// ConfidenceLevel represents the malicious confidence level
type ConfidenceLevel string

const (
	Low    ConfidenceLevel = "Low"
	Medium ConfidenceLevel = "Medium"
	High   ConfidenceLevel = "High"
)

// GetMaliciousConfidenceLevel returns the confidence level based on the score
// Score ranges:
// 0-30: low
// 30-70: medium
// 70-100: high
func GetMaliciousConfidenceLevel(score int) ConfidenceLevel {
	switch {
	case score >= 70:
		return High
	case score >= 30:
		return Medium
	default:
		return Low
	}
}
