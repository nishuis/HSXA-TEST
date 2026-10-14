package rules

import (
	"regexp"
	"strings"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// vncVersionRe captures the RFB protocol version line, for example
// "RFB 003.008".
var vncVersionRe = regexp.MustCompile(`RFB (\d{3})\.(\d{3})`)

// vncProducts names the VNC implementations that announce themselves.
var vncProducts = []struct {
	token   string
	product string
}{
	{"RealVNC", "RealVNC"},
	{"TightVNC", "TightVNC"},
	{"UltraVNC", "UltraVNC"},
	{"TigerVNC", "TigerVNC"},
	{"LibVNCServer", "LibVNCServer"},
	{"Apple", "Apple Remote Desktop"},
}

func vncSet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolVNC,
		Ports:    []int{5900, 5901},
		ProtoRules: []*rule.Rule{
			{
				Name: "vnc-rfb-version", MatchType: rule.MatchRegex,
				Pattern: `(?s)^RFB \d{3}\.\d{3}`, Weight: score.WeightProtoSignature, Priority: 100,
			},
			{
				Name: "vnc-rfb-security-types", MatchType: rule.MatchRegex,
				Pattern: `(?s)RFB \d{3}\.\d{3}\n`, Weight: score.WeightProtoWeak, Priority: 50,
			},
		},
		Extract: extractVNC,
	}
}

// extractVNC reports the RFB version normalised to "major.minor", which is how
// the protocol version is quoted ("RFB 003.008" is version 3.8).
func extractVNC(in rule.Input) (rule.Findings, bool) {
	m := vncVersionRe.FindStringSubmatch(in.Text())
	if m == nil {
		return rule.Findings{}, false
	}
	version := trimLeadingZeros(m[1]) + "." + trimLeadingZeros(m[2])
	product := "VNC"
	for _, candidate := range vncProducts {
		if strings.Contains(in.Text(), candidate.token) {
			product = candidate.product
			break
		}
	}
	return rule.Findings{
		Product: product,
		Version: version,
		Rule:    "vnc-rfb-handshake",
		Weight:  score.WeightProductStrong,
	}, true
}

func trimLeadingZeros(s string) string {
	t := strings.TrimLeft(s, "0")
	if t == "" {
		return "0"
	}
	return t
}
