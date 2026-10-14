package rules

import (
	"bytes"
	"regexp"
	"strings"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// mariadbVersionRe extracts the server version out of the MariaDB handshake
// banner, which repeats the version several times:
//
//	5.5.5-10.6.12-MariaDB-1:10.6.12+maria~ubu2004
var mariadbVersionRe = regexp.MustCompile(`(\d+\.\d+\.\d+)-MariaDB`)

func mysqlSet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolMySQL,
		Ports:    []int{3306},
		ProtoRules: []*rule.Rule{
			{
				// Greeting: 3 byte payload length, 1 byte sequence id, protocol
				// version 0x0a, then the NUL terminated server version.
				Name: "mysql-handshake-packet", MatchType: rule.MatchRegex,
				Pattern: `(?s)^.{3}\x00\x0a\d`, Weight: score.WeightProtoSignature, Priority: 100,
			},
			{
				Name: "mysql-native-password", MatchType: rule.MatchContains,
				Pattern: "mysql_native_password", Weight: score.WeightProtoSignature, Priority: 90,
			},
			{
				Name: "mysql-sha2-password", MatchType: rule.MatchContains,
				Pattern: "caching_sha2_password", Weight: score.WeightProtoSignature, Priority: 90,
			},
			{
				Name: "mysql-auth-switch", MatchType: rule.MatchContains,
				Pattern: "mysql_clear_password", Weight: score.WeightProtoWeak, Priority: 40,
			},
		},
		Extract: extractMySQL,
	}
}

// extractMySQL reads the server version string out of a MySQL or MariaDB
// handshake packet and splits the distribution suffix off, so that
// "8.0.32-0ubuntu0.22.04.1" becomes version 8.0.32 with os_hint Ubuntu.
func extractMySQL(in rule.Input) (rule.Findings, bool) {
	b := in.Bytes
	if len(b) > 6 && b[4] == 0x0a {
		if end := bytes.IndexByte(b[5:], 0); end > 0 {
			raw := string(b[5 : 5+end])
			return rule.Findings{
				Product: mysqlProduct(raw),
				Version: mysqlVersion(raw),
				OSHint:  osFromText(raw),
				Rule:    "mysql-handshake",
				Weight:  score.WeightProductStrong,
			}, true
		}
	}
	text := in.Text()
	if raw := firstLine(in.Bytes); strings.Contains(strings.ToLower(raw), "mariadb") {
		return rule.Findings{
			Product: "MariaDB",
			Version: mysqlVersion(raw),
			Rule:    "mysql-banner-text",
			Weight:  score.WeightProductWeak,
		}, true
	}
	if strings.Contains(text, "mysql_native_password") || strings.Contains(text, "caching_sha2_password") {
		return rule.Findings{
			Product: "MySQL",
			Rule:    "mysql-auth-plugin",
			Weight:  score.WeightProductWeak,
		}, true
	}
	return rule.Findings{}, false
}

func mysqlProduct(raw string) string {
	if strings.Contains(strings.ToLower(raw), "mariadb") {
		return "MariaDB"
	}
	return "MySQL"
}

func mysqlVersion(raw string) string {
	if strings.Contains(strings.ToLower(raw), "mariadb") {
		if m := mariadbVersionRe.FindStringSubmatch(raw); m != nil {
			return m[1]
		}
	}
	if i := strings.IndexByte(raw, '-'); i > 0 {
		raw = raw[:i]
	}
	return cleanVersion(raw)
}
