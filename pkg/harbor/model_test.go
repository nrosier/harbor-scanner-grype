package harbor

import "testing"

// Baseline test: always green, so the workspace has a test suite from
// the very first run.
func TestSeverityRankOrder(t *testing.T) {
	order := []Severity{SevUnknown, SevNegligible, SevLow, SevMedium, SevHigh, SevCritical}
	for i := 1; i < len(order); i++ {
		if order[i].Rank() <= order[i-1].Rank() {
			t.Fatalf("%s must rank above %s", order[i], order[i-1])
		}
	}
}
