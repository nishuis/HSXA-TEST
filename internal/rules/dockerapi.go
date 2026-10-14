package rules

import (
	"regexp"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// dockerVersionRe captures the engine version of a GET /version response.
// The leading byte class keeps it from matching the "ApiVersion" key.
var dockerVersionRe = regexp.MustCompile(`(?:^|[^A-Za-z"])"Version"\s*:\s*"([\d.]+)"`)

// dockerAPIVersionRe captures the API version reported by the Api-Version
// header or by the "ApiVersion" JSON key.
var dockerAPIVersionRe = regexp.MustCompile(`(?i)(?:api-version:\s*|"ApiVersion"\s*:\s*")([\d.]+)`)

func dockerAPISet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolDockerAPI,
		Ports:    []int{2375, 2376},
		ProtoRules: []*rule.Rule{
			{
				Name: "docker-api-version-header", MatchType: rule.MatchRegex,
				Pattern: `(?i)api-version:\s*\d`,
				Weight:  score.WeightProtoDistinctive, Priority: 100,
			},
			{
				Name: "docker-experimental-header", MatchType: rule.MatchRegex,
				Pattern: `(?i)docker-experimental:`,
				Weight:  score.WeightProtoDistinctive, Priority: 95,
			},
			{
				Name: "docker-api-version-body", MatchType: rule.MatchRegex,
				Pattern: `(?s)"ApiVersion"\s*:\s*"`,
				Weight:  score.WeightProtoDistinctive, Priority: 90,
			},
		},
		Extract: extractDockerAPI,
	}
}

// extractDockerAPI reports the Docker Engine version when the payload is a
// GET /version response; the API version alone is not an engine version.
func extractDockerAPI(in rule.Input) (rule.Findings, bool) {
	text := in.Text()
	if m := dockerVersionRe.FindStringSubmatch(text); m != nil {
		return rule.Findings{
			Product: "Docker Engine",
			Version: cleanVersion(m[1]),
			Rule:    "docker-version-response",
			Weight:  score.WeightProductStrong,
		}, true
	}
	if dockerAPIVersionRe.MatchString(text) {
		return rule.Findings{
			Product: "Docker Engine",
			Rule:    "docker-api-version",
			Weight:  score.WeightProductWeak,
		}, true
	}
	return rule.Findings{}, false
}
