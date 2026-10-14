package rules

import (
	"regexp"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// esVersionRe captures the version number of the root "version" object of an
// Elasticsearch response.
var esVersionRe = regexp.MustCompile(`(?s)"number"\s*:\s*"([\d.]+)"`)

func elasticsearchSet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolElasticsearch,
		Ports:    []int{9200, 9300},
		ProtoRules: []*rule.Rule{
			{
				Name: "elasticsearch-product-header", MatchType: rule.MatchRegex,
				Pattern: `(?i)x-elastic-product:\s*elasticsearch`,
				Weight:  score.WeightProtoDistinctive, Priority: 100,
			},
			{
				Name: "elasticsearch-tagline", MatchType: rule.MatchRegex,
				Pattern: `(?i)"tagline"\s*:\s*"you know, for search"`,
				Weight:  score.WeightProtoDistinctive, Priority: 95,
			},
			{
				Name: "elasticsearch-root-response", MatchType: rule.MatchRegex,
				Pattern: `(?s)"cluster_name".*?"lucene_version"`,
				Weight:  score.WeightProtoDistinctive, Priority: 90,
			},
		},
		Extract: extractElasticsearch,
	}
}

// extractElasticsearch confirms Elasticsearch and reports the version from the
// root document of the search API.
func extractElasticsearch(in rule.Input) (rule.Findings, bool) {
	version := ""
	if m := esVersionRe.FindStringSubmatch(in.Text()); m != nil {
		version = cleanVersion(m[1])
	}
	weight := score.WeightProductWeak
	if version != "" {
		weight = score.WeightProductStrong
	}
	return rule.Findings{
		Product: "Elasticsearch",
		Version: version,
		Rule:    "elasticsearch-root-response",
		Weight:  weight,
	}, true
}
