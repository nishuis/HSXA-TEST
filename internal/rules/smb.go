package rules

import (
	"regexp"
	"strings"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// sambaVersionRe captures a Samba version string, which appears in the session
// setup response of a SMB1 negotiation.
var sambaVersionRe = regexp.MustCompile(`(?i)Samba\s+(\d+[\w.\-]*)`)

// smbDialectRe matches the SMB1 dialect string of a negotiate response.
var smbDialectRe = regexp.MustCompile(`(?i)NT LM 0\.12`)

func smbSet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolSMB,
		Ports:    []int{445, 139},
		ProtoRules: []*rule.Rule{
			{
				Name: "smb1-negotiate-response", MatchType: rule.MatchBinary,
				Pattern: `\xffSMB`, Offset: 0, Weight: score.WeightProtoSignature, Priority: 100,
			},
			{
				Name: "smb2-negotiate-response", MatchType: rule.MatchBinary,
				Pattern: `\xfeSMB`, Offset: 0, Weight: score.WeightProtoSignature, Priority: 100,
			},
			{
				Name: "smb-ntlmssp", MatchType: rule.MatchContains,
				Pattern: "NTLMSSP", Weight: score.WeightProtoWeak, Priority: 40,
			},
		},
		Extract: extractSMB,
	}
}

// extractSMB names the SMB implementation: Samba on unix-like systems, the
// Windows SMB stack otherwise.
func extractSMB(in rule.Input) (rule.Findings, bool) {
	text := in.Text()
	if m := sambaVersionRe.FindStringSubmatch(text); m != nil {
		return rule.Findings{
			Product: "Samba",
			Version: cleanVersion(m[1]),
			Rule:    "smb-samba-dialect",
			Weight:  score.WeightProductStrong,
		}, true
	}
	if smbDialectRe.MatchString(text) || containsAny(text, "Windows", "MICROSOFT") {
		return rule.Findings{
			Product: "Microsoft Windows",
			OSHint:  "Windows",
			Rule:    "smb-negotiate-dialect",
			Weight:  score.WeightProductStrong,
		}, true
	}
	if containsAny(text, "Samba") {
		return rule.Findings{
			Product: "Samba",
			Rule:    "smb-samba-dialect",
			Weight:  score.WeightProductWeak,
		}, true
	}
	return rule.Findings{}, false
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if sub != "" && strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
