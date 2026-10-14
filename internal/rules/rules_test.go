package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hsxa-banner-fingerprint/internal/engine"
	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/model"
)

// TestBuiltinRegistryIsComplete guards the protocol coverage of plan.md §2.1.
func TestBuiltinRegistryIsComplete(t *testing.T) {
	reg, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v", err)
	}
	want := []string{
		"SSH", "FTP", "SMTP", "POP3", "IMAP", "Telnet", "Redis", "HTTP",
		"Elasticsearch", "Docker API", "MySQL", "PostgreSQL", "MongoDB",
		"SMB", "VNC", "RDP", "Memcached",
	}
	got := reg.Protocols()
	if len(got) != len(want) {
		t.Fatalf("protocols = %v, want %d entries", got, len(want))
	}
	for i, name := range want {
		if got[i] != name {
			t.Errorf("protocol %d = %q, want %q", i, got[i], name)
		}
		set := reg.Set(name)
		if set == nil {
			t.Fatalf("protocol %q missing from the registry", name)
		}
		if len(set.ProtoRules) == 0 {
			t.Errorf("protocol %q has no signature rule", name)
		}
		if len(set.Ports) == 0 {
			t.Errorf("protocol %q has no port prior", name)
		}
		if set.RuleCount() == 0 {
			t.Errorf("protocol %q has no rules", name)
		}
	}
	if reg.RuleCount() < len(want) {
		t.Errorf("RuleCount = %d, suspiciously low", reg.RuleCount())
	}
	if n := len(reg.ByPort(22)); n != 1 {
		t.Errorf("ByPort(22) = %d sets, want 1", n)
	}
}

// TestPlainTextStaysUnknown guards against the false positives of R6: a
// payload with no protocol signature and a port with no prior must not be
// attributed to anything.
func TestPlainTextStaysUnknown(t *testing.T) {
	eng := testEngine(t)
	records := []model.ScanRecord{
		{IP: "1.1.1.1", Port: 9999, Banner: "Welcome to the internal file share."},
		{IP: "1.1.1.2", Port: 9999, Banner: `{"json":true,"nested":{"a":1}}`},
		{IP: "1.1.1.3", Port: 9999, Banner: strings.Repeat("x", 4096)},
		{IP: "1.1.1.4", Port: 9999, Banner: ""},
	}
	for _, rec := range records {
		got := eng.Identify(rec)
		if got.Protocol != model.ProtocolUnknown {
			t.Errorf("%q on port %d identified as %s", rec.Banner, rec.Port, got.Protocol)
		}
		if got.Product != "" || got.Version != "" || got.OSHint != "" || got.Confidence != 0 {
			t.Errorf("%q produced evidence: %+v", rec.Banner, got)
		}
	}
}

// TestProtocolKeywordAloneIsNotEnough checks that a mention of a product name
// without its protocol context does not produce a product.
func TestProtocolKeywordAloneIsNotEnough(t *testing.T) {
	eng := testEngine(t)
	// "nginx" and "Apache" appear, but there is no HTTP status line and the
	// port has no prior, so nothing may be claimed.
	rec := model.ScanRecord{IP: "1.1.1.1", Port: 9999, Banner: "deploy log: restarted nginx and Apache today"}
	got := eng.Identify(rec)
	if got.Protocol != model.ProtocolUnknown || got.Product != "" {
		t.Errorf("got %+v, want unknown with no product", got)
	}
}

func TestLoadOverlaysExtendsAndOverrides(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "http.yaml"), `
protocol: HTTP
product_rules:
  - name: http-server-myapp
    match_type: regex
    pattern: '(?i)server:\s*myapp/([0-9.]+)'
    product: MyApp
    version_group: 1
    weight: 0.15
    priority: 400
  - name: http-server-nginx
    match_type: regex
    pattern: '(?i)server:\s*nginx(?:/([0-9]+))?'
    product: nginx
    version_group: 1
    weight: 0.15
    priority: 280
`)
	writeFile(t, filepath.Join(dir, "custom.yaml"), `
protocol: MyProto
ports: [12345]
protocol_rules:
  - name: myproto-signature
    match_type: prefix
    pattern: "\xffMYPROTO"
    weight: 0.60
    priority: 100
product_rules:
  - name: myproto-product
    match_type: regex
    pattern: 'MyProto/([\d.]+)'
    product: MyProto
    version_group: 1
    weight: 0.15
    priority: 100
`)
	reg, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	if err := LoadOverlays(reg, dir); err != nil {
		t.Fatalf("LoadOverlays: %v", err)
	}

	http := reg.Set(model.ProtocolHTTP)
	found := false
	for _, r := range http.ProductRules {
		if r.Name == "http-server-myapp" {
			found = true
		}
	}
	if !found {
		t.Error("external product rule was not added to HTTP")
	}
	nginx := 0
	for _, r := range http.ProductRules {
		if r.Name == "http-server-nginx" {
			nginx++
		}
	}
	if nginx != 1 {
		t.Errorf("http-server-nginx appears %d times, want exactly 1 (override, not append)", nginx)
	}

	eng := engine.New(reg)
	got := eng.Identify(model.ScanRecord{IP: "1.1.1.1", Port: 80,
		Banner: "HTTP/1.1 200 OK\r\nServer: MyApp/2.5\r\n\r\n"})
	if got.Product != "MyApp" || got.Version != "2.5" {
		t.Errorf("overlay product rule did not fire: %+v", got)
	}
	got = eng.Identify(model.ScanRecord{IP: "1.1.1.2", Port: 12345,
		Banner: "MyProto/3.1 welcome"})
	if got.Protocol != "MyProto" || got.Product != "MyProto" || got.Version != "3.1" {
		t.Errorf("overlay protocol did not fire: %+v", got)
	}
}

func TestLoadOverlaysErrors(t *testing.T) {
	// A missing directory is not an error: the overlay is optional (FR-11).
	reg, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	if err := LoadOverlays(reg, filepath.Join(t.TempDir(), "does-not-exist")); err != nil {
		t.Errorf("missing overlay dir should be tolerated, got %v", err)
	}

	bad := []struct {
		name string
		body string
	}{
		{"no-protocol", "product_rules: []\n"},
		{"invalid-yaml", "protocol: [unclosed\n"},
		{"bad-regex", "protocol: HTTP\nproduct_rules:\n  - name: broken\n    match_type: regex\n    pattern: '(['\n"},
	}
	for _, tc := range bad {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "x.yaml"), tc.body)
		reg, err := Builtin()
		if err != nil {
			t.Fatalf("Builtin: %v", err)
		}
		if err := LoadOverlays(reg, dir); err == nil {
			t.Errorf("%s: LoadOverlays() = nil, want a start-up failure", tc.name)
		}
	}
}

func TestMergeRules(t *testing.T) {
	base := []*rule.Rule{{Name: "a", Pattern: "1"}, {Name: "b", Pattern: "2"}}
	merged := mergeRules(base, []*rule.Rule{
		{Name: "b", Pattern: "22"},
		{Name: "c", Pattern: "3"},
		nil,
	})
	if len(merged) != 3 {
		t.Fatalf("merged = %d rules, want 3", len(merged))
	}
	byName := map[string]string{}
	for _, r := range merged {
		byName[r.Name] = r.Pattern
	}
	if byName["a"] != "1" || byName["b"] != "22" || byName["c"] != "3" {
		t.Errorf("merged rules = %+v", byName)
	}
	if base[1].Pattern != "2" {
		t.Error("merge must not mutate the base slice")
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
