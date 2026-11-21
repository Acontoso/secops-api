package models

import "testing"

func TestGetMaliciousConfidenceLevelCharacterization(t *testing.T) {
	tests := []struct {
		name  string
		score int
		want  string
	}{
		{name: "negative below range", score: -100, want: "Low"},
		{name: "negative boundary", score: -1, want: "Low"},
		{name: "lower bound", score: 0, want: "Low"},
		{name: "just below medium", score: 29, want: "Low"},
		{name: "medium lower bound", score: 30, want: "Medium"},
		{name: "mid medium", score: 50, want: "Medium"},
		{name: "just below high", score: 69, want: "Medium"},
		{name: "high lower bound", score: 70, want: "High"},
		{name: "high", score: 99, want: "High"},
		{name: "upper bound", score: 100, want: "High"},
		{name: "above range", score: 101, want: "High"},
		{name: "far above range", score: 1 << 20, want: "High"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(GetMaliciousConfidenceLevel(tt.score)); got != tt.want {
				t.Errorf("GetMaliciousConfidenceLevel(%d) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}
