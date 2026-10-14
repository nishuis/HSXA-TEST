package rules

import (
	"regexp"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// memcachedVersionRe captures the version of a VERSION or "STAT version" line.
var memcachedVersionRe = regexp.MustCompile(`(?im)^(?:VERSION|STAT version)\s+(\S+)`)

func memcachedSet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolMemcached,
		Ports:    []int{11211},
		ProtoRules: []*rule.Rule{
			{
				Name: "memcached-version-reply", MatchType: rule.MatchRegex,
				Pattern: `(?im)^(?:VERSION\s+\S+|STAT version\s+\S+)`,
				Weight:  score.WeightProtoSignature, Priority: 100,
			},
			{
				Name: "memcached-client-error", MatchType: rule.MatchContains,
				Pattern: "CLIENT_ERROR", Weight: score.WeightProtoWeak, Priority: 60,
			},
			{
				Name: "memcached-server-error", MatchType: rule.MatchContains,
				Pattern: "SERVER_ERROR", Weight: score.WeightProtoWeak, Priority: 55,
			},
			{
				Name: "memcached-error-reply", MatchType: rule.MatchRegex,
				Pattern: `(?im)^ERROR\s*$`, Weight: score.WeightProtoWeak, Priority: 50,
			},
		},
		Extract: extractMemcached,
	}
}

// extractMemcached confirms Memcached and reports the version when the server
// answered a VERSION or "stats" command.
func extractMemcached(in rule.Input) (rule.Findings, bool) {
	version := ""
	if m := memcachedVersionRe.FindStringSubmatch(in.Text()); m != nil {
		version = cleanVersion(m[1])
	}
	weight := score.WeightProductWeak
	if version != "" {
		weight = score.WeightProductStrong
	}
	return rule.Findings{
		Product: "Memcached",
		Version: version,
		Rule:    "memcached-reply",
		Weight:  weight,
	}, true
}
