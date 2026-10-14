package rules

import (
	"regexp"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// telnetProductRe matches the few telnet daemons that name themselves.
var telnetProductRe = regexp.MustCompile(`(?i)(BusyBox|Alpine|Netkit|Linux [\d.]+|Ubuntu|Debian|OpenWrt|RouterOS)`)

func telnetSet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolTelnet,
		Ports:    []int{23, 2323},
		ProtoRules: []*rule.Rule{
			{
				Name: "telnet-iac-negotiation", MatchType: rule.MatchBinary,
				Pattern: `\xff\xfd`, Offset: 0, Weight: score.WeightProtoSignature, Priority: 100,
			},
			{
				Name: "telnet-iac-subnegotiation", MatchType: rule.MatchBinary,
				Pattern: `\xff\xfa`, Offset: 0, Weight: score.WeightProtoSignature, Priority: 95,
			},
			{
				// Inline negotiations carry the same IAC WILL/DO bytes further
				// into the payload. Byte literals only: a regex cannot compare
				// raw bytes at or above 0x80.
				Name: "telnet-iac-will-inline", MatchType: rule.MatchContains,
				Pattern: "\xff\xfb", Weight: score.WeightProtoSignature, Priority: 90,
			},
			{
				Name: "telnet-iac-do-inline", MatchType: rule.MatchContains,
				Pattern: "\xff\xfd", Weight: score.WeightProtoWeak, Priority: 85,
			},
			{
				Name: "telnet-login-prompt", MatchType: rule.MatchRegex,
				Pattern: `(?im)^(?:login|Username|Password)\s*:\s*$`, Weight: score.WeightProtoWeak, Priority: 40,
			},
		},
		Extract: extractTelnet,
	}
}

// extractTelnet reports the telnet daemon or distribution named in the banner
// text; most telnet banners carry no product information at all.
func extractTelnet(in rule.Input) (rule.Findings, bool) {
	m := telnetProductRe.FindStringSubmatch(in.Text())
	if m == nil {
		return rule.Findings{}, false
	}
	name := m[1]
	os := osFromText(name)
	version := cleanVersion(numericPrefix(name))
	product := name
	if os != "" {
		product = ""
	}
	if product == "" && os == "" && version == "" {
		return rule.Findings{}, false
	}
	return rule.Findings{
		Product: product,
		Version: version,
		OSHint:  os,
		Rule:    "telnet-banner-text",
		Weight:  score.WeightProductWeak,
	}, true
}
