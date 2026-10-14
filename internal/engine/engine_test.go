package engine

import (
	"strings"
	"testing"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/model"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	reg := rule.NewRegistry()
	set := &rule.Set{
		Protocol: model.ProtocolSSH,
		Ports:    []int{22},
		ProtoRules: []*rule.Rule{
			{Name: "ssh", MatchType: rule.MatchRegex, Pattern: `(?i)^SSH-\d+\.\d+-`, Weight: 0.60, Priority: 10},
		},
		ProductRules: []*rule.Rule{
			{Name: "openssh", MatchType: rule.MatchRegex, Pattern: `OpenSSH_([\w.]+)`, Product: "OpenSSH", VersionGroup: 1, Weight: 0.15},
		},
	}
	if err := reg.Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Compile(); err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return New(reg)
}

func TestIdentifyDegradesInsteadOfFailing(t *testing.T) {
	eng := newTestEngine(t)
	tests := []struct {
		name       string
		record     model.ScanRecord
		protocol   string
		product    string
		version    string
		confidence float64
	}{
		{"empty-banner-known-port", model.ScanRecord{IP: "1.1.1.1", Port: 22}, model.ProtocolSSH, "", "", 0.35},
		{"empty-banner-unknown-port", model.ScanRecord{IP: "1.1.1.2", Port: 9999}, model.ProtocolUnknown, "", "", 0.0},
		{"garbage-on-known-port", model.ScanRecord{IP: "1.1.1.3", Port: 22, Banner: "\x00\x01\x02"}, model.ProtocolSSH, "", "", 0.35},
		{"undecodable-payload", model.ScanRecord{IP: "1.1.1.4", Port: 22, Banner: "%%%", Encoding: "base64"}, model.ProtocolSSH, "", "", 0.35},
		{"recognised", model.ScanRecord{IP: "1.1.1.5", Port: 22, Banner: "SSH-2.0-OpenSSH_9.6"}, model.ProtocolSSH, "OpenSSH", "9.6", 0.90},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := eng.Identify(tc.record)
			if got.IP != tc.record.IP || got.Port != tc.record.Port {
				t.Errorf("record echoed as %s:%d, want %s:%d", got.IP, got.Port, tc.record.IP, tc.record.Port)
			}
			if got.Protocol != tc.protocol || got.Product != tc.product || got.Version != tc.version {
				t.Errorf("got %s/%s/%s, want %s/%s/%s",
					got.Protocol, got.Product, got.Version, tc.protocol, tc.product, tc.version)
			}
			if got.Confidence != tc.confidence {
				t.Errorf("confidence = %.2f, want %.2f", got.Confidence, tc.confidence)
			}
			if got.OSHint != "" {
				t.Errorf("expected empty os_hint, got %q", got.OSHint)
			}
		})
	}
}

func TestIdentifyNeverPanicsOnHostileInput(t *testing.T) {
	eng := newTestEngine(t)
	hostile := []string{
		"", strings.Repeat("A", 100000), strings.Repeat(`\x`, 5000),
		string([]byte{0xff, 0xfe, 0x00, 0x01}), "%s%s%s%n", "\x00",
		strings.Repeat("(", 1000), "\r\n\r\n\r\n", "\xff\xfd\x18\xff\xfa\x00\x01\xff\xf0",
	}
	for i, banner := range hostile {
		for _, encoding := range []string{"", "auto", "text", "hex"} {
			rec := model.ScanRecord{IP: "9.9.9.9", Port: 22, Banner: banner, Encoding: encoding}
			got := eng.Identify(rec)
			if got.Protocol == "" {
				t.Fatalf("case %d/%s: protocol must never be empty", i, encoding)
			}
			if got.Confidence < 0 || got.Confidence > 1 {
				t.Fatalf("case %d/%s: confidence out of range: %v", i, encoding, got.Confidence)
			}
		}
	}
}

func TestIdentifyBatchKeepsOrderAndCardinality(t *testing.T) {
	eng := newTestEngine(t)
	records := []model.ScanRecord{
		{IP: "a", Port: 22, Banner: "SSH-2.0-OpenSSH_9.6"},
		{IP: "b", Port: 9999},
		{IP: "c", Port: 22, Banner: "\x00\x01"},
		{IP: "d", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1"},
	}
	got, elapsed := eng.IdentifyBatchWithStats(records)
	if len(got) != len(records) {
		t.Fatalf("got %d results for %d records", len(got), len(records))
	}
	for i, r := range records {
		if got[i].IP != r.IP {
			t.Fatalf("result %d is %s, want %s (order not preserved)", i, got[i].IP, r.IP)
		}
	}
	if elapsed < 0 {
		t.Errorf("elapsed = %d", elapsed)
	}
	// A failed record inside the batch must not change its neighbours.
	if got[0].Product != "OpenSSH" || got[3].Version != "8.9p1" {
		t.Errorf("batch degraded neighbours: %+v", got)
	}
}

func TestIdentifyWithoutRegistry(t *testing.T) {
	eng := New(nil)
	got := eng.Identify(model.ScanRecord{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_9.6"})
	if got.Protocol != model.ProtocolUnknown || got.Confidence != 0 {
		t.Errorf("nil registry result = %+v, want unknown/0", got)
	}
	if eng.Registry() != nil {
		t.Error("Registry() should mirror the nil registry")
	}
}

func TestIdentifyWithEvidence(t *testing.T) {
	eng := newTestEngine(t)
	rec := model.ScanRecord{IP: "1.2.3.4", Port: 22, Banner: `SSH-2.0-OpenSSH_9.6\r\n`}
	res, ev := eng.IdentifyWithEvidence(rec)
	if res.Product != "OpenSSH" {
		t.Fatalf("product = %q", res.Product)
	}
	if ev.ProtocolRule != "ssh" || ev.ProductRule != "openssh" {
		t.Errorf("evidence = %+v", ev)
	}
	if ev.Encoding != "text" {
		t.Errorf("evidence encoding = %q", ev.Encoding)
	}
}
