// Package extract resolves the product, version and OS evidence of a payload
// that has already been attributed to a protocol.
//
// The protocol rule sets do the matching; this package is the single place
// where the extracted tokens are normalised into the vocabulary of the output
// contract (canonical product spelling, clean version strings, known OS
// names).
package extract

import (
	"strings"

	"hsxa-banner-fingerprint/internal/engine/rule"
)

// Product runs the protocol's product rules in priority order and falls back
// to the protocol's bespoke extractor. The boolean is false when the payload
// carries no product evidence, in which case the caller must leave product,
// version and os_hint empty.
func Product(set *rule.Set, in rule.Input) (rule.Findings, bool) {
	if set == nil {
		return rule.Findings{}, false
	}
	f, ok := set.Product(in)
	if !ok {
		return rule.Findings{}, false
	}
	f.Product = CanonicalProduct(f.Product)
	f.Version = CleanVersion(f.Version)
	f.OSHint = NormalizeOS(f.OSHint)
	return f, true
}

// productAliases canonicalises the vendor spelling of product names found in
// banners. Only entries whose banner spelling differs from the canonical name
// need to appear here.
var productAliases = map[string]string{
	"openssh":           "OpenSSH",
	"open ssh":          "OpenSSH",
	"dropbear":          "Dropbear",
	"libssh":            "libssh",
	"proftpd":           "ProFTPD",
	"vsftpd":            "vsftpd",
	"pure-ftpd":         "Pure-FTPd",
	"filezilla":         "FileZilla",
	"glftpd":            "glFTPd",
	"wordpress":         "WordPress",
	"apache coyote":     "Tomcat",
	"apache-coyote":     "Tomcat",
	"microsoft-iis":     "IIS",
	"openssl":           "OpenSSL",
	"postgresql":        "PostgreSQL",
	"postgres":          "PostgreSQL",
	"mongodb":           "MongoDB",
	"memcached":         "Memcached",
	"elasticsearch":     "Elasticsearch",
	"tigervnc":          "TigerVNC",
	"realvnc":           "RealVNC",
	"ultravnc":          "UltraVNC",
	"tightvnc":          "TightVNC",
	"libvncserver":      "LibVNCServer",
	"microsoft rdp":     "Microsoft RDP",
	"microsoft windows": "Microsoft Windows",
	"mysql":             "MySQL",
	"mariadb":           "MariaDB",
}

// CanonicalProduct maps the vendor spelling of a product to the name used in
// results. Unknown names pass through unchanged.
func CanonicalProduct(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if canonical, ok := productAliases[strings.ToLower(name)]; ok {
		return canonical
	}
	return name
}

// CleanVersion normalises a captured version string: surrounding whitespace
// and quotes are removed, a leading "v" is dropped, and everything from the
// first whitespace on is discarded. Strings that cannot be a version at all
// collapse to the empty string.
func CleanVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"'`)
	if v == "" {
		return ""
	}
	if i := strings.IndexAny(v, " \t\r\n,;)"); i >= 0 {
		v = v[:i]
	}
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && isDigit(v[1]) {
		v = v[1:]
	}
	v = strings.Trim(v, "-.")
	if v == "" || !containsDigit(v) || len(v) > 64 {
		return ""
	}
	return v
}

// osAliases maps banner tokens to the canonical os_hint vocabulary of
// plan.md §10-4.
var osAliases = []struct{ token, canonical string }{
	{"ubuntu", "Ubuntu"},
	{"debian", "Debian"},
	{"raspbian", "Raspbian"},
	{"centos", "CentOS"},
	{"red hat", "Red Hat"},
	{"redhat", "Red Hat"},
	{"rhel", "Red Hat"},
	{"fedora", "Fedora"},
	{"rocky", "Rocky Linux"},
	{"almalinux", "AlmaLinux"},
	{"alpine", "Alpine"},
	{"amazon linux", "Amazon Linux"},
	{"amzn", "Amazon Linux"},
	{"opensuse", "openSUSE"},
	{"suse", "SUSE"},
	{"gentoo", "Gentoo"},
	{"arch linux", "Arch"},
	{"kali", "Kali"},
	{"freebsd", "FreeBSD"},
	{"openbsd", "OpenBSD"},
	{"netbsd", "NetBSD"},
	{"windows", "Windows"},
	{"wince", "Windows"},
	{"win64", "Windows"},
	{"win32", "Windows"},
}

// NormalizeOS maps a raw OS token taken from a banner to the canonical
// os_hint value, and returns "" for tokens that carry no OS meaning.
func NormalizeOS(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.Trim(raw, "()[]")
	if raw == "" {
		return ""
	}
	for _, a := range osAliases {
		if strings.Contains(raw, a.token) {
			return a.canonical
		}
	}
	return ""
}

// OSFromText searches a banner fragment for a known OS or distribution token
// and returns its canonical name, or "" when the fragment carries none. It
// must only be applied to fragments where an OS hint is expected, such as an
// SSH comment or an Apache Server header parenthesis.
func OSFromText(s string) string { return NormalizeOS(s) }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func containsDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			return true
		}
	}
	return false
}
