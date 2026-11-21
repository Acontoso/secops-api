package models

// ConfidenceLevel represents the malicious confidence level
type ConfidenceLevel string

const (
	Low    ConfidenceLevel = "Low"
	Medium ConfidenceLevel = "Medium"
	High   ConfidenceLevel = "High"
)

// GetMaliciousConfidenceLevel returns Low for scores below 30, Medium for scores
// from 30 through 69, and High for scores of 70 or more.
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
