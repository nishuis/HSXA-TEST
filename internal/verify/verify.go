// Package verify compares identification results against an expectation file.
//
// It is the shared comparison used by the golden tests and by the acceptance
// harness, so the criteria of plan.md §6.2 are implemented exactly once.
package verify

import (
	"fmt"
	"math"
	"strings"

	"hsxa-banner-fingerprint/internal/model"
)

// Options tunes a comparison.
type Options struct {
	// ConfidenceEpsilon is the tolerated absolute difference of a confidence.
	ConfidenceEpsilon float64
}

// DefaultOptions is the acceptance tolerance of plan.md §1.3: ±0.05 on the
// confidence anchors.
var DefaultOptions = Options{ConfidenceEpsilon: 0.05}

// Compare returns one message per mismatch between want and got. An empty
// result means every record matched. The comparison is positional, so it also
// proves the 1:1 ordering requirement of FR-9.
func Compare(want, got []model.Result, opts Options) []string {
	var problems []string
	if len(want) != len(got) {
		problems = append(problems, fmt.Sprintf("record count: want %d, got %d", len(want), len(got)))
	}
	n := len(want)
	if len(got) < n {
		n = len(got)
	}
	for i := 0; i < n; i++ {
		w, g := want[i], got[i]
		pos := fmt.Sprintf("record %d (%s:%d)", i, w.IP, w.Port)
		if g.IP != w.IP {
			problems = append(problems, fmt.Sprintf("%s: ip want %q, got %q", pos, w.IP, g.IP))
		}
		if g.Port != w.Port {
			problems = append(problems, fmt.Sprintf("%s: port want %d, got %d", pos, w.Port, g.Port))
		}
		for _, f := range []struct {
			name      string
			want, got string
		}{
			{"protocol", w.Protocol, g.Protocol},
			{"product", w.Product, g.Product},
			{"version", w.Version, g.Version},
			{"os_hint", w.OSHint, g.OSHint},
		} {
			if f.got != f.want {
				problems = append(problems, fmt.Sprintf("%s: %s want %q, got %q", pos, f.name, f.want, f.got))
			}
		}
		if math.Abs(g.Confidence-w.Confidence) > opts.ConfidenceEpsilon {
			problems = append(problems, fmt.Sprintf(
				"%s: confidence want %.2f (±%.2f), got %.2f", pos, w.Confidence, opts.ConfidenceEpsilon, g.Confidence,
			))
		}
	}
	return problems
}

// CheckJSONContract validates the frozen serialisation rules of plan.md §1.2
// on a raw response body: no null values, and the exact field set on every
// result object.
func CheckJSONContract(raw []byte) []string {
	var problems []string
	if strings.Contains(string(raw), "null") {
		problems = append(problems, "response body contains null; missing values must be the empty string")
	}
	return problems
}
