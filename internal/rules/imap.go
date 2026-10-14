package rules

import (
	"regexp"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// imapProducts lists the IMAP server banners.
var imapProducts = []struct {
	re      *regexp.Regexp
	product string
}{
	{regexp.MustCompile(`(?i)\bDovecot\b`), "Dovecot"},
	{regexp.MustCompile(`(?i)\bCyrus\b`), "Cyrus IMAP"},
	{regexp.MustCompile(`(?i)\bCourier-IMAP\b`), "Courier-IMAP"},
	{regexp.MustCompile(`(?i)\bZimbra\b`), "Zimbra"},
	{regexp.MustCompile(`(?i)Microsoft Exchange`), "Microsoft Exchange"},
	{regexp.MustCompile(`(?i)\bUW-?IMAP\b`), "UW-IMAP"},
	{regexp.MustCompile(`(?i)\bGmail\b`), "Gmail"},
	{regexp.MustCompile(`(?i)\bMailEnable\b`), "MailEnable"},
}

func imapSet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolIMAP,
		Ports:    []int{143, 993},
		ProtoRules: []*rule.Rule{
			{
				Name: "imap-capability", MatchType: rule.MatchRegex,
				Pattern: `(?is)^\* OK[^\r\n]{0,400}\bIMAP4(?:rev1|rev2)?\b`,
				Weight:  score.WeightProtoSignature, Priority: 100,
			},
			{
				Name: "imap-greeting", MatchType: rule.MatchRegex,
				Pattern: `(?is)^\* (?:OK|PREAUTH|BYE)\b`, Weight: score.WeightProtoWeak, Priority: 50,
			},
		},
		Extract: extractIMAP,
	}
}

// extractIMAP identifies the IMAP server from its untagged greeting. Only the
// servers that quote a version in the greeting (Cyrus, Zimbra) get one.
func extractIMAP(in rule.Input) (rule.Findings, bool) {
	text := in.Text()
	for _, candidate := range imapProducts {
		if !candidate.re.MatchString(text) {
			continue
		}
		version := cleanVersion(firstVersion(text))
		weight := score.WeightProductWeak
		if version != "" {
			weight = score.WeightProductStrong
		}
		return rule.Findings{
			Product: candidate.product,
			Version: version,
			Rule:    "imap-greeting",
			Weight:  weight,
		}, true
	}
	return rule.Findings{}, false
}
