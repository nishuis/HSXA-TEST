package rules

import (
	"regexp"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// sshLineRe matches an SSH identification line anywhere in a payload:
//
//	SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
var sshLineRe = regexp.MustCompile(`(?m)^SSH-(\d+)\.(\d+)-([^ \t\r\n]+)([^\r\n]*)`)

func sshSet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolSSH,
		Ports:    []int{22, 2222},
		ProtoRules: []*rule.Rule{
			{
				Name:      "ssh-identification-string",
				MatchType: rule.MatchRegex,
				Pattern:   `(?i)^SSH-\d+\.\d+-`,
				Weight:    score.WeightProtoSignature,
				Priority:  100,
			},
			{
				Name:      "ssh-identification-string-inline",
				MatchType: rule.MatchRegex,
				Pattern:   `(?i)\r?\nSSH-\d+\.\d+-`,
				Weight:    score.WeightProtoWeak,
				Priority:  50,
			},
		},
		Extract: extractSSH,
	}
}

// extractSSH parses the SSH identification string. The software token carries
// the product and version ("OpenSSH_8.9p1") and the comment field usually
// carries the distribution ("Ubuntu-3ubuntu0.4").
func extractSSH(in rule.Input) (rule.Findings, bool) {
	m := sshLineRe.FindStringSubmatch(in.Text())
	if m == nil {
		return rule.Findings{}, false
	}
	product, version := splitProductVersion(m[3])
	if product == "" {
		return rule.Findings{}, false
	}
	os := osFromText(m[4])
	if os == "" {
		os = osFromText(m[3])
	}
	return rule.Findings{
		Product: product,
		Version: version,
		OSHint:  os,
		Rule:    "ssh-software-string",
		Weight:  score.WeightProductStrong,
	}, true
}
