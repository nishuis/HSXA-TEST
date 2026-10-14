package rules

import (
	"regexp"
	"strings"

	"hsxa-banner-fingerprint/internal/engine/extract"
)

// versionTokenRe captures the leading dotted numeric version of a token, such
// as "1.24.0" out of "1.24.0-ubuntu0.2".
var versionTokenRe = regexp.MustCompile(`^\d+(?:\.\d+)*`)

// versionSearchRe finds the first version-looking token of a banner fragment,
// such as "2.4.24" in "Cyrus IMAP4 v2.4.24 server ready".
var versionSearchRe = regexp.MustCompile(`(?i)\bv?(\d+\.\d+(?:\.\d+)*)`)

// firstLine returns the first line of a payload, tolerating CRLF and LF.
func firstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// splitProductVersion splits a vendor token such as "OpenSSH_8.9p1" or
// "Cisco-1.25" into its product and version halves, at the last separator
// whose suffix starts with a digit.
func splitProductVersion(token string) (product, version string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", ""
	}
	for i := len(token) - 1; i > 0; i-- {
		switch token[i] {
		case '_', '-':
		default:
			continue
		}
		rest := token[i+1:]
		if rest == "" || rest[0] < '0' || rest[0] > '9' {
			continue
		}
		return token[:i], rest
	}
	return token, ""
}

// osFromText returns the canonical OS hint of a banner fragment, or "".
func osFromText(s string) string { return extract.NormalizeOS(s) }

// cleanVersion normalises a captured version token.
func cleanVersion(s string) string { return extract.CleanVersion(s) }

// numericPrefix returns the leading dotted numeric version of s, or "".
func numericPrefix(s string) string { return versionTokenRe.FindString(s) }

// firstVersion returns the first version-looking token of a banner fragment,
// or "" when the fragment carries none.
func firstVersion(s string) string {
	if m := versionSearchRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// fields splits a banner fragment into whitespace separated fields.
func fields(s string) []string { return strings.Fields(s) }
