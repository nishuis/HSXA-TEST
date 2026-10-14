package rules

import (
	"regexp"

	"hsxa-banner-fingerprint/internal/engine/rule"
	"hsxa-banner-fingerprint/internal/engine/score"
	"hsxa-banner-fingerprint/internal/model"
)

// ftpProducts lists the FTP server banners ProFTPD, vsftpd, Pure-FTPd,
// FileZilla Server, Microsoft FTP Service and friends. The first match wins.
var ftpProducts = []struct {
	name    string
	re      *regexp.Regexp
	product string
}{
	{"proftpd", regexp.MustCompile(`(?i)\bProFTPD\s+(\d+[\w.\-]*)`), "ProFTPD"},
	{"vsftpd", regexp.MustCompile(`(?i)\bvsFTPd\s+(\d+[\w.\-]*)`), "vsftpd"},
	{"pure-ftpd", regexp.MustCompile(`(?i)Pure-FTPd[^\r\n]{0,80}?(\d+\.\d+[\w.\-]*)`), "Pure-FTPd"},
	{"filezilla", regexp.MustCompile(`(?i)FileZilla Server\s+(\d+[\w.\-]*)`), "FileZilla"},
	{"microsoft-ftp", regexp.MustCompile(`(?i)Microsoft FTP Service`), "Microsoft FTP Service"},
	{"serv-u", regexp.MustCompile(`(?i)Serv-U(?: FTP Server)?\s*(\d+[\w.\-]*)?`), "Serv-U"},
	{"wu-ftpd", regexp.MustCompile(`(?i)\bwu-?ftpd\s*(\d+[\w.\-]*)?`), "wu-ftpd"},
	{"glftpd", regexp.MustCompile(`(?i)\bglFTPd\s*(\d+[\w.\-]*)?`), "glFTPd"},
	{"pyftpdlib", regexp.MustCompile(`(?i)pyftpdlib\s*(\d+[\w.\-]*)?`), "pyftpdlib"},
}

// parenGroupRe extracts the first parenthesised group of a banner; FTP servers
// use it for the distribution name.
var parenGroupRe = regexp.MustCompile(`\(([^)]+)\)`)

func ftpSet() *rule.Set {
	return &rule.Set{
		Protocol: model.ProtocolFTP,
		Ports:    []int{21},
		ProtoRules: []*rule.Rule{
			{
				Name: "ftp-greeting-named", MatchType: rule.MatchRegex,
				Pattern: `(?is)^220[ -][^\r\n]{0,120}?(proftpd|vsftpd|pure-ftpd|filezilla|microsoft ftp|wu-ftpd|serv-u|pyftpdlib|glftpd)`,
				Weight:  score.WeightProtoSignature, Priority: 100,
			},
			{
				Name: "ftp-greeting-generic", MatchType: rule.MatchRegex,
				Pattern: `(?s)^220[ -]`, Weight: score.WeightProtoWeak, Priority: 10,
			},
		},
		Extract: extractFTP,
	}
}

// extractFTP identifies the FTP server from its 220 greeting.
func extractFTP(in rule.Input) (rule.Findings, bool) {
	text := in.Text()
	for _, candidate := range ftpProducts {
		m := candidate.re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		version := ""
		if len(m) > 1 {
			version = cleanVersion(m[1])
		}
		weight := score.WeightProductWeak
		if version != "" {
			weight = score.WeightProductStrong
		}
		return rule.Findings{
			Product: candidate.product,
			Version: version,
			OSHint:  ftpOSHint(text),
			Rule:    "ftp-server-banner",
			Weight:  weight,
		}, true
	}
	return rule.Findings{}, false
}

// ftpOSHint reads the distribution out of the first parenthesised group, which
// is where ProFTPD and friends put it: "220 ProFTPD 1.3.7 Server (Debian)".
func ftpOSHint(text string) string {
	m := parenGroupRe.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return osFromText(m[1])
}
