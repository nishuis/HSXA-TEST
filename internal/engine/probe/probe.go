// Package probe decides which protocols a payload may belong to.
//
// Content signatures are the primary evidence; the port prior table only
// breaks ties and supplies a fallback candidate when the payload carries no
// signal at all (plan.md §2.2, R3).
package probe

import (
	"sort"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// PortPriorRule is the name reported for a candidate that only the port prior
// table supports.
const PortPriorRule = "port-prior"

// TLSRecordRule is the name reported for a TLS record payload.
const TLSRecordRule = "tls-record"

// Candidate is one protocol hypothesis for a payload.
type Candidate struct {
	Protocol string
	Rule     string
	Weight   float64
	Groups   []string
	// PortConsistent reports that the record's port is one of the protocol's
	// well-known ports.
	PortConsistent bool
	// PortOnly reports that the payload carried no signature for this
	// protocol and the port prior is the only evidence.
	PortOnly bool
	// TLSOnly reports a TLS record payload: HTTP by port, but with no readable
	// plaintext, so no product or version can be extracted (plan.md R2).
	TLSOnly bool
}

// Decide ranks the protocol hypotheses for in, best candidate first. The
// result is empty only when the payload carries no signature and the port has
// no prior.
func Decide(reg *rule.Registry, in rule.Input) []Candidate {
	if reg == nil {
		return nil
	}
	var out []Candidate
	seen := make(map[string]bool)
	for _, m := range reg.MatchSignature(in) {
		c := Candidate{
			Protocol: m.Protocol,
			Rule:     m.Rule.Name,
			Weight:   m.Rule.EffectiveWeight(),
			Groups:   m.Groups,
		}
		if set := reg.Set(m.Protocol); set != nil {
			c.PortConsistent = hasPort(set.Ports, in.Port)
		}
		out = append(out, c)
		seen[m.Protocol] = true
	}
	if len(out) == 0 && looksLikeTLS(in.Bytes) {
		// A TLS record only proves HTTP where the port prior says so (443,
		// 8443). On any other port the record is opaque, and the port prior
		// loop below supplies the only honest candidate (plan.md R2).
		if set := reg.Set(model.ProtocolHTTP); set != nil && hasPort(set.Ports, in.Port) {
			out = append(out, Candidate{
				Protocol:       model.ProtocolHTTP,
				Rule:           TLSRecordRule,
				Weight:         score.WeightProtoTLSOnly,
				PortConsistent: true,
				TLSOnly:        true,
			})
			seen[model.ProtocolHTTP] = true
		}
	}
	for _, set := range reg.ByPort(in.Port) {
		if seen[set.Protocol] {
			continue
		}
		out = append(out, Candidate{
			Protocol:       set.Protocol,
			Rule:           PortPriorRule,
			Weight:         score.WeightProtoPortOnly,
			PortConsistent: true,
			PortOnly:       true,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Weight != out[j].Weight {
			return out[i].Weight > out[j].Weight
		}
		if out[i].PortConsistent != out[j].PortConsistent {
			return out[i].PortConsistent
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out
}

// looksLikeTLS reports whether the payload starts with a TLS record header
// (or the legacy SSLv2 record header) instead of plaintext.
func looksLikeTLS(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	if b[0] == 0x80 && b[2] == 0x01 {
		return true // SSLv2 ClientHello
	}
	return b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04
}

func hasPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}
