package rules

import (
	"bytes"
	"regexp"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// pgParamRe captures a ParameterStatus value: the parameter name, a NUL
// terminator, the value and its NUL terminator.
var pgParamRe = regexp.MustCompile(`([A-Za-z_]+)\x00([^\x00]*)\x00`)

func postgresqlSet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolPostgreSQL,
		Ports:    []int{5432},
		ProtoRules: []*rule.Rule{
			{
				Name: "postgres-parameter-status", MatchType: rule.MatchContains,
				Pattern: "server_version", Weight: score.WeightProtoSignature, Priority: 100,
			},
			{
				Name: "postgres-brand", MatchType: rule.MatchContains,
				Pattern: "PostgreSQL", Weight: score.WeightProtoSignature, Priority: 95,
			},
			{
				// AuthenticationOk / AuthenticationRequest / ErrorResponse /
				// ReadyForQuery: one type byte plus a 4 byte length and at
				// least one body byte. The body byte is matched as "." because
				// a regex cannot compare raw bytes at or above 0x80.
				Name: "postgres-message-header", MatchType: rule.MatchRegex,
				Pattern: `(?s)^[RNESK]?\x00\x00\x00.`, Weight: score.WeightProtoWeak, Priority: 40,
			},
			{
				Name: "postgres-error-fields", MatchType: rule.MatchContains,
				Pattern: "SFATAL", Weight: score.WeightProtoWeak, Priority: 35,
			},
		},
		Extract: extractPostgreSQL,
	}
}

// extractPostgreSQL reads the server_version parameter out of a PostgreSQL
// ParameterStatus message:
//
//	server_version\x0016.1 (Debian 16.1-1.pgdg120+1)\x00
func extractPostgreSQL(in rule.Input) (rule.Findings, bool) {
	b := in.Bytes
	idx := bytes.Index(b, []byte("server_version\x00"))
	if idx < 0 {
		return rule.Findings{}, false
	}
	rest := b[idx:]
	m := pgParamRe.FindSubmatch(rest)
	if m == nil {
		return rule.Findings{}, false
	}
	raw := string(m[2])
	return rule.Findings{
		Product: "PostgreSQL",
		Version: cleanVersion(numericPrefix(raw)),
		OSHint:  osFromText(raw),
		Rule:    "postgres-server-version",
		Weight:  score.WeightProductStrong,
	}, true
}
