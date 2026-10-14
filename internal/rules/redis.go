package rules

import (
	"regexp"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// redisVersionRe captures the version reported by an INFO response.
var redisVersionRe = regexp.MustCompile(`(?i)redis_version:(\S+)`)

func redisSet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolRedis,
		Ports:    []int{6379},
		ProtoRules: []*rule.Rule{
			{
				Name: "redis-error-reply", MatchType: rule.MatchRegex,
				Pattern: `(?s)^-(?:NOAUTH|ERR|DENIED|WRONGPASS|WRONGTYPE|MOVED|ASK|LOADING|MASTERDOWN|READONLY|MISCONF)\b`,
				Weight:  score.WeightProtoSignature, Priority: 100,
			},
			{
				Name: "redis-info-fields", MatchType: rule.MatchRegex,
				Pattern: `(?s)^# Server`, Weight: score.WeightProtoSignature, Priority: 95,
			},
			{
				Name: "redis-pong", MatchType: rule.MatchRegex,
				Pattern: `(?s)^\+PONG\b`, Weight: score.WeightProtoSignature, Priority: 90,
			},
			{
				Name: "redis-bulk-reply", MatchType: rule.MatchRegex,
				Pattern: `(?s)^\$\d+\r\n`, Weight: score.WeightProtoWeak, Priority: 80,
			},
			{
				Name: "redis-array-reply", MatchType: rule.MatchRegex,
				Pattern: `(?s)^\*\d+\r\n`, Weight: score.WeightProtoWeak, Priority: 70,
			},
			{
				Name: "redis-command-inline", MatchType: rule.MatchRegex,
				Pattern: `(?s)^(?:PING|INFO|AUTH|COMMAND|CONFIG)\b.*\r\n`, Weight: score.WeightProtoWeak, Priority: 60,
			},
		},
		ProductRules: []*rule.Rule{
			{
				Name: "redis-info-version", MatchType: rule.MatchRegex,
				Pattern: `(?i)redis_version:(\S+)`, Product: "Redis",
				VersionGroup: 1, Weight: score.WeightProductStrong, Priority: 100,
			},
		},
		Extract: extractRedis,
	}
}

// extractRedis confirms Redis when the payload is a RESP reply. Authentication
// and protocol errors identify the product but carry no version, which is what
// makes the Redis acceptance record land at a lower confidence than the other
// six.
func extractRedis(in rule.Input) (rule.Findings, bool) {
	b := in.Bytes
	if len(b) == 0 {
		return rule.Findings{}, false
	}
	switch b[0] {
	case '-', '+', '$', '*', ':':
	default:
		return rule.Findings{}, false
	}
	return rule.Findings{
		Product: "Redis",
		Rule:    "redis-resp-reply",
		Weight:  score.WeightProductWeak,
	}, true
}
