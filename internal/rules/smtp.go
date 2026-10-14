package rules

import (
	"regexp"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// smtpProducts lists the SMTP banners of the common mail transfer agents.
var smtpProducts = []struct {
	re      *regexp.Regexp
	product string
}{
	{regexp.MustCompile(`(?i)\bpostfix\b`), "Postfix"},
	{regexp.MustCompile(`(?i)\bexim\s+(\d+[\w.\-]*)`), "Exim"},
	{regexp.MustCompile(`(?i)\bsendmail\s+(\d+[\w.\-/]*)`), "Sendmail"},
	{regexp.MustCompile(`(?i)Microsoft (?:E)?SMTP MAIL Service(?:,?\s*Version:\s*([\w.\-]+))?`), "Microsoft Exchange"},
	{regexp.MustCompile(`(?i)\bOpenSMTPD\s*([\w.\-]*)?`), "OpenSMTPD"},
	{regexp.MustCompile(`(?i)\bHaraka\b`), "Haraka"},
	{regexp.MustCompile(`(?i)\bMailEnable\b`), "MailEnable"},
	{regexp.MustCompile(`(?i)\bqmail\b`), "qmail"},
}

func smtpSet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolSMTP,
		Ports:    []int{25, 465, 587},
		ProtoRules: []*rule.Rule{
			{
				Name: "smtp-greeting-named", MatchType: rule.MatchRegex,
				Pattern: `(?is)^220[ -][^\r\n]{0,160}?(esmtp|smtp|postfix|exim|sendmail|exchange|opensmtpd|haraka|mailenable|qmail)`,
				Weight:  score.WeightProtoSignature, Priority: 100,
			},
			{
				Name: "smtp-session-verb", MatchType: rule.MatchRegex,
				Pattern: `(?is)^(?:EHLO|HELO) \S+`,
				Weight:  score.WeightProtoWeak, Priority: 60,
			},
			{
				Name: "smtp-mail-from", MatchType: rule.MatchRegex,
				Pattern: `(?is)^MAIL FROM:\s*<`,
				Weight:  score.WeightProtoSignature, Priority: 55,
			},
			{
				Name: "smtp-greeting-generic", MatchType: rule.MatchRegex,
				Pattern: `(?s)^220[ -]`, Weight: score.WeightProtoWeak, Priority: 10,
			},
		},
		Extract: extractSMTP,
	}
}

// extractSMTP identifies the mail transfer agent from its greeting.
func extractSMTP(in rule.Input) (rule.Findings, bool) {
	text := in.Text()
	for _, candidate := range smtpProducts {
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
			Rule:    "smtp-greeting",
			Weight:  weight,
		}, true
	}
	return rule.Findings{}, false
}
