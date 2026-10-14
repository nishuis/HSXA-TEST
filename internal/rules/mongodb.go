package rules

import (
	"bytes"
	"regexp"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// mongoVersionRe captures the MongoDB version out of a buildInfo response.
var mongoVersionRe = regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`)

// mongoHelloRe matches the command names of the MongoDB handshake and
// maintenance commands.
var mongoHelloRe = regexp.MustCompile(`(?si)(?:isMaster|ismaster|buildInfo|buildinfo|maxWireVersion|maxBsonObjectSize)`)

// MongoDB wire protocol opcodes, little endian, at offset 12 of a message:
// 2004 OP_MSG (0x07d4), 2002 OP_QUERY (0x07d2), 2013 OP_COMMAND (0x07dd).
var mongoOpcodes = [][]byte{
	{0xd4, 0x07},
	{0xd2, 0x07},
	{0xdd, 0x07},
}

// mongoWireHeader reports whether a payload starts with a MongoDB message
// header carrying a known opcode.
func mongoWireHeader(b []byte) bool {
	if len(b) < 14 {
		return false
	}
	for _, opcode := range mongoOpcodes {
		if bytes.HasPrefix(b[12:], opcode) {
			return true
		}
	}
	return false
}

// mongoEvidence reports whether a payload carries MongoDB content evidence.
func mongoEvidence(b []byte) bool {
	return mongoHelloRe.Match(b) || mongoWireHeader(b)
}

func mongodbSet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolMongoDB,
		Ports:    []int{27017},
		ProtoRules: []*rule.Rule{
			{
				// The command name sits behind a BSON type byte, so only the
				// name itself is anchored on.
				Name: "mongo-hello-command", MatchType: rule.MatchRegex,
				Pattern: `(?si)(?:isMaster|ismaster|buildInfo|buildinfo|helloOk|maxWireVersion|maxBsonObjectSize)`,
				Weight:  score.WeightProtoSignature, Priority: 100,
			},
			{
				Name: "mongo-op-msg", MatchType: rule.MatchBinary,
				Pattern: string([]byte{0xd4, 0x07}), Offset: 12,
				Weight: score.WeightProtoSignature, Priority: 90,
			},
			{
				Name: "mongo-op-query", MatchType: rule.MatchBinary,
				Pattern: string([]byte{0xd2, 0x07}), Offset: 12,
				Weight: score.WeightProtoSignature, Priority: 85,
			},
			{
				Name: "mongo-op-command", MatchType: rule.MatchBinary,
				Pattern: string([]byte{0xdd, 0x07}), Offset: 12,
				Weight: score.WeightProtoSignature, Priority: 80,
			},
		},
		Extract: extractMongoDB,
	}
}

// extractMongoDB confirms MongoDB and, when the payload happens to carry a
// buildInfo response, reports its version.
func extractMongoDB(in rule.Input) (rule.Findings, bool) {
	if !mongoEvidence(in.Bytes) {
		return rule.Findings{}, false
	}
	version := ""
	if m := mongoVersionRe.FindStringSubmatch(in.Text()); m != nil {
		version = cleanVersion(m[1])
	}
	weight := score.WeightProductWeak
	if version != "" {
		weight = score.WeightProductStrong
	}
	return rule.Findings{
		Product: "MongoDB",
		Version: version,
		Rule:    "mongo-wire-protocol",
		Weight:  weight,
	}, true
}
