package rule

import (
	"strings"
	"testing"
)

func TestRuleCompileValidation(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		wantErr string
	}{
		{"ok-prefix", Rule{Name: "r", Kind: KindProtocol, MatchType: MatchPrefix, Pattern: "SSH-"}, ""},
		{"ok-regex", Rule{Name: "r", Kind: KindProduct, MatchType: MatchRegex, Pattern: `(\d+)`}, ""},
		{"unknown-kind", Rule{Name: "r", Kind: "banana", MatchType: MatchPrefix, Pattern: "x"}, "unknown kind"},
		{"empty-pattern", Rule{Name: "r", Kind: KindProtocol, MatchType: MatchPrefix}, "empty pattern"},
		{"missing-match-type", Rule{Name: "r", Kind: KindProtocol, Pattern: "x"}, "missing match_type"},
		{"unknown-match-type", Rule{Name: "r", Kind: KindProtocol, MatchType: "glob", Pattern: "x"}, "unknown match_type"},
		{"bad-regex", Rule{Name: "r", Kind: KindProtocol, MatchType: MatchRegex, Pattern: "(["}, "compile regex"},
		{"negative-offset", Rule{Name: "r", Kind: KindProtocol, MatchType: MatchBinary, Pattern: "x", Offset: -1}, "negative offset"},
		{
			"high-byte-escape-in-regex",
			Rule{Name: "r", Kind: KindProtocol, MatchType: MatchRegex, Pattern: `^\x03\x00..\x0e[\xd0\xe0]`},
			"raw byte",
		},
		{
			"high-byte-braced-escape-in-regex",
			Rule{Name: "r", Kind: KindProtocol, MatchType: MatchRegex, Pattern: `\x{ff}`},
			"raw byte",
		},
		{
			"high-byte-escape-is-fine-in-literals",
			Rule{Name: "r", Kind: KindProtocol, MatchType: MatchContains, Pattern: `\xffSMB`},
			"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rule.Compile()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Compile() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Compile() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Compile() error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestRuleMatch(t *testing.T) {
	prefix := &Rule{Name: "p", Kind: KindProtocol, MatchType: MatchPrefix, Pattern: "SSH-"}
	contains := &Rule{Name: "c", Kind: KindProtocol, MatchType: MatchContains, Pattern: `\xffSMB`}
	offset := &Rule{Name: "b", Kind: KindProtocol, MatchType: MatchBinary, Pattern: "mysql", Offset: 4}
	regex := &Rule{Name: "re", Kind: KindProduct, MatchType: MatchRegex, Pattern: `nginx/([\w.]+)`}
	for _, r := range []*Rule{prefix, contains, offset, regex} {
		if err := r.Compile(); err != nil {
			t.Fatalf("compile %s: %v", r.Name, err)
		}
	}

	if _, ok := prefix.Match(Input{Bytes: []byte("SSH-2.0-x")}); !ok {
		t.Error("prefix rule did not match")
	}
	if _, ok := prefix.Match(Input{Bytes: []byte("xSSH-")}); ok {
		t.Error("prefix rule matched mid payload")
	}
	if _, ok := contains.Match(Input{Bytes: []byte("\xffSMB\x00")}); !ok {
		t.Error("byte-literal contains rule did not match")
	}
	if _, ok := offset.Match(Input{Bytes: []byte{0x00, 0x00, 0x00, 0x00, 'm', 'y', 's', 'q', 'l'}}); !ok {
		t.Error("binary rule did not match at offset")
	}
	if _, ok := offset.Match(Input{Bytes: []byte("mysql")}); ok {
		t.Error("binary rule matched past the end of the payload")
	}
	groups, ok := regex.Match(Input{Bytes: []byte("Server: nginx/1.24.0")})
	if !ok || len(groups) < 2 || groups[1] != "1.24.0" {
		t.Errorf("regex groups = %v, ok = %v", groups, ok)
	}
}

func TestRuleEvidence(t *testing.T) {
	r := &Rule{
		Name: "http-server-jetty", Kind: KindProduct, MatchType: MatchRegex,
		Pattern: `(?i)jetty\((\d+(?:\.\d+)+)`, Product: "Jetty", VersionGroup: 1,
		OSHint: "Debian", Priority: 5,
	}
	if err := r.Compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	groups, ok := r.Match(Input{Bytes: []byte("Server: Jetty(9.4.51)")})
	if !ok {
		t.Fatal("jetty rule did not match")
	}
	f := r.FindingsFor(groups)
	if f.Product != "Jetty" || f.Version != "9.4.51" || f.OSHint != "Debian" {
		t.Errorf("findings = %+v", f)
	}
	if f.Rule != "http-server-jetty" || f.Weight != DefaultProductWeight {
		t.Errorf("rule/weight = %q/%.2f", f.Rule, f.Weight)
	}
	if r.EffectiveWeight() != DefaultProductWeight {
		t.Errorf("EffectiveWeight = %v, want default product weight", r.EffectiveWeight())
	}

	// An OS capture group overrides the literal hint.
	r2 := &Rule{Name: "x", Kind: KindProduct, MatchType: MatchRegex, Pattern: `\(([^)]*)\)`, OSGroup: 1, OSHint: "fallback"}
	if err := r2.Compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	groups, _ = r2.Match(Input{Bytes: []byte("Server: nginx (Ubuntu)")})
	if f := r2.FindingsFor(groups); f.OSHint != "Ubuntu" {
		t.Errorf("OSHint = %q, want Ubuntu", f.OSHint)
	}

	// A version template renders $1 references.
	r3 := &Rule{Name: "t", Kind: KindProduct, MatchType: MatchRegex, Pattern: `v(\d+)`, VersionTemplate: "$1.0"}
	if err := r3.Compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	groups, _ = r3.Match(Input{Bytes: []byte("v7")})
	if f := r3.FindingsFor(groups); f.Version != "7.0" {
		t.Errorf("Version = %q, want 7.0", f.Version)
	}
	if got := ExpandTemplate("$1-$2-$9", []string{"", "a", "b"}); got != "a-b-" {
		t.Errorf("ExpandTemplate = %q", got)
	}
}

func TestSetCompileAndOrder(t *testing.T) {
	set := &Set{
		Protocol: "TEST",
		Ports:    []int{1234},
		ProtoRules: []*Rule{
			{Name: "low", MatchType: MatchPrefix, Pattern: "a", Priority: 1},
			{Name: "high", MatchType: MatchPrefix, Pattern: "b", Priority: 100},
		},
		ProductRules: []*Rule{{Name: "p1", MatchType: MatchPrefix, Pattern: "c", Product: "P"}},
		Extract: func(Input) (Findings, bool) {
			return Findings{Product: "from-extractor"}, true
		},
	}
	if err := set.Compile(); err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if set.ProtoRules[0].Name != "high" {
		t.Errorf("rules not sorted by priority: %q first", set.ProtoRules[0].Name)
	}
	if set.ProtoRules[0].Kind != KindProtocol || set.ProductRules[0].Kind != KindProduct {
		t.Error("kinds not inferred from the rule group")
	}
	if set.ProtoRules[0].Protocol != "TEST" {
		t.Error("protocol not inherited from the set")
	}
	if set.RuleCount() != 3 {
		t.Errorf("RuleCount = %d, want 3", set.RuleCount())
	}

	// Declarative rules win over the extractor.
	f, ok := set.Product(Input{Bytes: []byte("ccc")})
	if !ok || f.Product != "P" {
		t.Errorf("Product() = %+v, %v", f, ok)
	}
	// The extractor is the fallback.
	f, ok = set.Product(Input{Bytes: []byte("zzz")})
	if !ok || f.Product != "from-extractor" || f.Weight != DefaultProductWeight {
		t.Errorf("Product() fallback = %+v, %v", f, ok)
	}

	if _, _, ok := set.Signature(Input{Bytes: []byte("aaa")}); !ok {
		t.Error("signature did not match")
	}
}

func TestSetCompileRejectsDuplicates(t *testing.T) {
	set := &Set{
		Protocol: "TEST",
		ProtoRules: []*Rule{
			{Name: "dup", MatchType: MatchPrefix, Pattern: "a"},
			{Name: "dup", MatchType: MatchPrefix, Pattern: "b"},
		},
	}
	if err := set.Compile(); err == nil {
		t.Fatal("Compile() = nil, want duplicate rule error")
	}
	if err := (&Set{Protocol: ""}).Compile(); err == nil {
		t.Fatal("Compile() = nil for an empty protocol name")
	}
	if err := (&Set{Protocol: "X", ProtoRules: []*Rule{{MatchType: MatchPrefix, Pattern: "a"}}}).Compile(); err == nil {
		t.Fatal("Compile() = nil for an unnamed rule")
	}
}

func TestRegistry(t *testing.T) {
	reg := NewRegistry()
	a := &Set{Protocol: "A", Ports: []int{1, 2},
		ProtoRules: []*Rule{{Name: "a1", MatchType: MatchPrefix, Pattern: "aa"}}}
	b := &Set{Protocol: "B", Ports: []int{2},
		ProtoRules: []*Rule{{Name: "b1", MatchType: MatchPrefix, Pattern: "bb"}}}
	if err := reg.Register(a); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Register(b); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Register(a); err == nil {
		t.Fatal("duplicate protocol accepted")
	}
	if err := reg.Register(nil); err == nil {
		t.Fatal("nil set accepted")
	}
	if err := reg.Register(&Set{}); err == nil {
		t.Fatal("empty protocol accepted")
	}
	if err := reg.Compile(); err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if got := reg.Protocols(); len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Errorf("Protocols = %v", got)
	}
	if got := reg.RuleCount(); got != 2 {
		t.Errorf("RuleCount = %d, want 2", got)
	}
	if reg.Set("A") != a || reg.Set("nope") != nil {
		t.Error("Set lookup failed")
	}
	if got := reg.ByPort(2); len(got) != 2 {
		t.Errorf("ByPort(2) = %d sets, want 2", len(got))
	}
	if matches := reg.MatchSignature(Input{Bytes: []byte("bb!")}); len(matches) != 1 || matches[0].Protocol != "B" {
		t.Errorf("MatchSignature = %+v", matches)
	}

	// Replace swaps the set of an existing protocol and can add a new one.
	replacement := &Set{Protocol: "A", ProtoRules: []*Rule{{Name: "a2", MatchType: MatchPrefix, Pattern: "zz"}}}
	if err := reg.Replace(replacement); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if err := reg.Compile(); err != nil {
		t.Fatalf("Compile after Replace: %v", err)
	}
	if reg.Set("A") != replacement {
		t.Error("Replace did not swap the set")
	}
	extra := &Set{Protocol: "C", ProtoRules: []*Rule{{Name: "c1", MatchType: MatchPrefix, Pattern: "cc"}}}
	if err := reg.Replace(extra); err != nil {
		t.Fatalf("Replace new: %v", err)
	}
	if err := reg.Compile(); err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(reg.Protocols()) != 3 {
		t.Errorf("Protocols after Replace = %v", reg.Protocols())
	}
	if err := reg.Replace(nil); err == nil {
		t.Error("Replace(nil) accepted")
	}
}
