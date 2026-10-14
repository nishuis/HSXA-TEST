package extract

import (
	"testing"

	"hsxa-banner-fingerprint/internal/engine/rule"
)

func TestCanonicalProduct(t *testing.T) {
	tests := map[string]string{
		"openssh":           "OpenSSH",
		"OpenSSH":           "OpenSSH",
		"dropbear":          "Dropbear",
		"proftpd":           "ProFTPD",
		"apache coyote":     "Tomcat",
		"microsoft-iis":     "IIS",
		"mongodb":           "MongoDB",
		"  nginx  ":         "nginx",
		"":                  "",
		"SomeVendorProduct": "SomeVendorProduct",
	}
	for in, want := range tests {
		if got := CanonicalProduct(in); got != want {
			t.Errorf("CanonicalProduct(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCleanVersion(t *testing.T) {
	tests := map[string]string{
		"8.9p1":           "8.9p1",
		"1.24.0":          "1.24.0",
		"v1.24.0":         "1.24.0",
		"V2.4.57":         "2.4.57",
		" 1.2.3 ":         "1.2.3",
		`"9.4.51"`:        "9.4.51",
		"1.2.3 (Ubuntu)":  "1.2.3",
		"3.0.5,":          "3.0.5",
		"1.2.3)":          "1.2.3",
		"":                "",
		"abc":             "",
		"unknown-version": "",
		"-1.2":            "1.2",
		"10.0.14393.0":    "10.0.14393.0",
	}
	for in, want := range tests {
		if got := CleanVersion(in); got != want {
			t.Errorf("CleanVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeOS(t *testing.T) {
	tests := map[string]string{
		"Ubuntu":            "Ubuntu",
		"(Debian)":          "Debian",
		"Ubuntu-3ubuntu0.4": "Ubuntu",
		"Win64":             "Windows",
		"windows":           "Windows",
		"FreeBSD":           "FreeBSD",
		"RHEL":              "Red Hat",
		"Amazon Linux":      "Amazon Linux",
		"OpenSSL/3.0.2":     "",
		"":                  "",
		"no distro here":    "",
	}
	for in, want := range tests {
		if got := NormalizeOS(in); got != want {
			t.Errorf("NormalizeOS(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProductResolution(t *testing.T) {
	set := &rule.Set{
		Protocol: "TEST",
		ProductRules: []*rule.Rule{
			{
				Name: "app", MatchType: rule.MatchRegex, Pattern: `App/([\d.]+)`,
				Product: "myapp", VersionGroup: 1, OSHint: "(Win64)",
				Weight: 0.15, Priority: 10,
			},
		},
		Extract: func(in rule.Input) (rule.Findings, bool) {
			return rule.Findings{Product: "Openssh", Version: " 8.9p1 ", Rule: "ext", Weight: 0.10}, true
		},
	}
	if err := set.Compile(); err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// The declarative rule wins and its captures are normalised.
	f, ok := Product(set, rule.Input{Bytes: []byte("Server: App/2.1.0")})
	if !ok {
		t.Fatal("declarative product rule did not fire")
	}
	if f.Product != "myapp" || f.Version != "2.1.0" || f.OSHint != "Windows" {
		t.Errorf("findings = %+v", f)
	}

	// The bespoke extractor is the fallback and is normalised too.
	f, ok = Product(set, rule.Input{Bytes: []byte("SSH-2.0-OpenSSH_8.9p1")})
	if !ok {
		t.Fatal("extractor fallback did not fire")
	}
	if f.Product != "OpenSSH" || f.Version != "8.9p1" {
		t.Errorf("findings = %+v", f)
	}

	// A nil set is not an error.
	if _, ok := Product(nil, rule.Input{Bytes: []byte("x")}); ok {
		t.Error("nil set should report no findings")
	}
}

func TestProductWithoutEvidence(t *testing.T) {
	set := &rule.Set{
		Protocol:     "TEST",
		ProductRules: []*rule.Rule{{Name: "app", MatchType: rule.MatchPrefix, Pattern: "App/", Product: "app"}},
	}
	if err := set.Compile(); err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if _, ok := Product(set, rule.Input{Bytes: []byte("nothing to see")}); ok {
		t.Error("no evidence should report no findings, so product stays empty")
	}
}
