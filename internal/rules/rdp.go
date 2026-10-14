package rules

import (
	"bytes"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// rdpX224 confirms reports whether a payload is a TPKT/X.224 connection
// confirm: version 0x03, reserved 0x00, a two byte length, the X.224 length
// indicator 0x0e and the confirmation code 0xd0.
func rdpX224Confirm(b []byte) bool { return rdpX224(b, 0xd0) }

// rdpX224Request reports whether a payload is a TPKT/X.224 connection request.
func rdpX224Request(b []byte) bool { return rdpX224(b, 0xe0) }

func rdpX224(b []byte, code byte) bool {
	return len(b) >= 6 && b[0] == 0x03 && b[1] == 0x00 && b[4] == 0x0e && b[5] == code
}

// rdpCookie is the routing token a client sends in the X.224 cookie.
var rdpCookie = []byte("Cookie: mstshash=")

// rdpNegotiationRequest is the RDP negotiation request structure.
var rdpNegotiationRequest = []byte{0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}

// rdpEvidence reports whether a payload carries RDP handshake content.
func rdpEvidence(b []byte) bool {
	return rdpX224Confirm(b) || rdpX224Request(b) ||
		bytes.Contains(b, rdpCookie) || bytes.Contains(b, rdpNegotiationRequest)
}

func rdpSet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolRDP,
		Ports:    []int{3389},
		ProtoRules: []*rule.Rule{
			{
				// Byte literals, not a regex: Go regexes match runes and cannot
				// compare raw bytes at or above 0x80.
				Name: "rdp-x224-connection-confirm", MatchType: rule.MatchBinary,
				Pattern: string([]byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0}),
				Weight:  score.WeightProtoSignature, Priority: 100,
			},
			{
				Name: "rdp-x224-connection-request", MatchType: rule.MatchBinary,
				Pattern: string([]byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0}),
				Weight:  score.WeightProtoSignature, Priority: 95,
			},
			{
				Name: "rdp-cookie", MatchType: rule.MatchContains,
				Pattern: "Cookie: mstshash=", Weight: score.WeightProtoSignature, Priority: 90,
			},
			{
				Name: "rdp-negotiation", MatchType: rule.MatchContains,
				Pattern: "\x01\x00\x08\x00\x03\x00\x00\x00", Weight: score.WeightProtoWeak, Priority: 40,
			},
		},
		Extract: extractRDP,
	}
}

// extractRDP confirms the Microsoft RDP stack. RDP is a Windows protocol, so
// the OS hint follows from the protocol itself; the version lives in the
// server certificate and is not available offline.
func extractRDP(in rule.Input) (rule.Findings, bool) {
	if !rdpEvidence(in.Bytes) {
		return rule.Findings{}, false
	}
	return rule.Findings{
		Product: "Microsoft RDP",
		OSHint:  "Windows",
		Rule:    "rdp-x224-handshake",
		Weight:  score.WeightProductStrong,
	}, true
}
