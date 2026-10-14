package probe

import (
	"testing"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

func testRegistry(t *testing.T) *rule.Registry {
	t.Helper()
	reg := rule.NewRegistry()
	sets := []*rule.Set{
		{
			Protocol: model.ProtocolSSH, Ports: []int{22},
			ProtoRules: []*rule.Rule{{Name: "ssh", MatchType: rule.MatchRegex, Pattern: `^SSH-\d`, Weight: score.WeightProtoSignature}},
		},
		{
			Protocol: model.ProtocolHTTP, Ports: []int{80, 443},
			ProtoRules: []*rule.Rule{{Name: "http", MatchType: rule.MatchRegex, Pattern: `(?s)^HTTP/1\.`, Weight: score.WeightProtoSignature}},
		},
		{
			Protocol: model.ProtocolMemcached, Ports: []int{11211},
			ProtoRules: []*rule.Rule{{Name: "mc", MatchType: rule.MatchContains, Pattern: "ERROR", Weight: score.WeightProtoWeak}},
		},
	}
	for _, s := range sets {
		if err := reg.Register(s); err != nil {
			t.Fatalf("Register(%s): %v", s.Protocol, err)
		}
	}
	if err := reg.Compile(); err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return reg
}

func TestDecidePrefersContentOverPort(t *testing.T) {
	reg := testRegistry(t)
	// An SSH banner on port 2222 must still be SSH even though 2222 has no
	// prior and the payload also matches nothing else.
	got := Decide(reg, rule.Input{Bytes: []byte("SSH-2.0-OpenSSH_8.9p1"), Port: 2222})
	if len(got) == 0 || got[0].Protocol != model.ProtocolSSH {
		t.Fatalf("candidates = %+v, want SSH first", got)
	}
	if got[0].PortConsistent {
		t.Error("2222 is not a registered SSH prior; PortConsistent should be false")
	}

	// A non-HTTP payload on port 80 must not be forced to HTTP.
	got = Decide(reg, rule.Input{Bytes: []byte("SSH-2.0-OpenSSH_8.9p1"), Port: 80})
	if got[0].Protocol != model.ProtocolSSH {
		t.Fatalf("candidates = %+v, want SSH first", got)
	}
	if got[0].Weight <= score.WeightProtoPortOnly {
		t.Errorf("content candidate weight %.2f should beat the port prior", got[0].Weight)
	}
}

func TestDecideFallsBackToPortPrior(t *testing.T) {
	reg := testRegistry(t)
	got := Decide(reg, rule.Input{Bytes: nil, Port: 22})
	if len(got) != 1 {
		t.Fatalf("candidates = %+v, want exactly one port candidate", got)
	}
	if !got[0].PortOnly || got[0].Weight != score.WeightProtoPortOnly || got[0].Protocol != model.ProtocolSSH {
		t.Errorf("candidate = %+v", got[0])
	}
	if got[0].Rule != PortPriorRule {
		t.Errorf("rule = %q, want %q", got[0].Rule, PortPriorRule)
	}

	if got := Decide(reg, rule.Input{Bytes: nil, Port: 4242}); len(got) != 0 {
		t.Errorf("unknown port candidates = %+v, want none", got)
	}
	if got := Decide(nil, rule.Input{Bytes: []byte("SSH-2.0-x"), Port: 22}); got != nil {
		t.Errorf("nil registry candidates = %+v, want nil", got)
	}
}

func TestDecideTLSRecord(t *testing.T) {
	reg := testRegistry(t)
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x2f, 0x01}
	got := Decide(reg, rule.Input{Bytes: hello, Port: 443})
	if len(got) == 0 || got[0].Protocol != model.ProtocolHTTP {
		t.Fatalf("candidates = %+v, want HTTP first", got)
	}
	if !got[0].TLSOnly {
		t.Error("TLSOnly should be set for a TLS record payload")
	}
	if got[0].Weight != score.WeightProtoTLSOnly {
		t.Errorf("weight = %.2f, want %.2f", got[0].Weight, score.WeightProtoTLSOnly)
	}
	if got[0].Rule != TLSRecordRule {
		t.Errorf("rule = %q, want %q", got[0].Rule, TLSRecordRule)
	}

	// The same bytes on an unrelated port keep the port prior only.
	got = Decide(reg, rule.Input{Bytes: hello, Port: 8081})
	if len(got) != 0 {
		t.Errorf("candidates = %+v, want none", got)
	}
}

func TestDecidePortPriorBreaksTies(t *testing.T) {
	// Two protocols with an identical-weight signature; the port prior decides
	// which one wins, and the protocol name breaks a remaining tie.
	reg := rule.NewRegistry()
	a := &rule.Set{Protocol: "ProtoA", Ports: []int{100},
		ProtoRules: []*rule.Rule{{Name: "a", MatchType: rule.MatchContains, Pattern: "shared", Weight: score.WeightProtoSignature}}}
	b := &rule.Set{Protocol: "ProtoB", Ports: []int{200},
		ProtoRules: []*rule.Rule{{Name: "b", MatchType: rule.MatchContains, Pattern: "shared", Weight: score.WeightProtoSignature}}}
	for _, s := range []*rule.Set{a, b} {
		if err := reg.Register(s); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	if err := reg.Compile(); err != nil {
		t.Fatalf("Compile: %v", err)
	}
	for _, tc := range []struct {
		port int
		want string
	}{{100, "ProtoA"}, {200, "ProtoB"}, {300, "ProtoA"}} {
		got := Decide(reg, rule.Input{Bytes: []byte("shared"), Port: tc.port})
		if len(got) == 0 || got[0].Protocol != tc.want {
			t.Errorf("port %d: first candidate %+v, want %s", tc.port, got, tc.want)
		}
	}
}
