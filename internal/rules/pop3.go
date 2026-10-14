package rules

import (
	"regexp"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// pop3Products lists the POP3 server banners.
var pop3Products = []struct {
	re      *regexp.Regexp
	product string
}{
	{regexp.MustCompile(`(?i)\bDovecot\b`), "Dovecot"},
	{regexp.MustCompile(`(?i)\bCourier\b`), "Courier"},
	{regexp.MustCompile(`(?i)\bQpopper\b(?:\s*\(?version\s+([\w.\-]+))?`), "Qpopper"},
	{regexp.MustCompile(`(?i)Microsoft Exchange`), "Microsoft Exchange"},
	{regexp.MustCompile(`(?i)\bMailEnable\b`), "MailEnable"},
	{regexp.MustCompile(`(?i)\bUW-?IMAP\b`), "UW-IMAP"},
}

func pop3Set() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolPOP3,
		Ports:    []int{110, 995},
		ProtoRules: []*rule.Rule{
			{
				Name: "pop3-greeting-ok", MatchType: rule.MatchRegex,
				Pattern: `(?s)^\+OK`, Weight: score.WeightProtoSignature, Priority: 100,
			},
			{
				// A bare "-ERR" is both a POP3 reply and a Redis error reply;
				// the two rules carry the same weight so the port prior decides
				// which protocol the record belongs to.
				Name: "pop3-greeting-err", MatchType: rule.MatchRegex,
				Pattern: `(?s)^-ERR`, Weight: score.WeightProtoSignature, Priority: 20,
			},
		},
		Extract: extractPOP3,
	}
}

// extractPOP3 identifies the POP3 server from its greeting. Only the servers
// that quote a version in the greeting (Qpopper, MailEnable) get one.
func extractPOP3(in rule.Input) (rule.Findings, bool) {
	text := in.Text()
	for _, candidate := range pop3Products {
		m := candidate.re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		version := ""
		if len(m) > 1 {
			version = cleanVersion(m[1])
		}
		weight := score.WeightProductWeak
		if version != "" {
			weight = score.WeightProductStrong
		}
		return rule.Findings{
			Product: candidate.product,
			Version: version,
			OSHint:  osFromText(firstLine(in.Bytes)),
			Rule:    "pop3-greeting",
			Weight:  weight,
		}, true
	}
	return rule.Findings{}, false
}
