// Package rules holds the built-in fingerprint rules and the loader for
// external YAML overlays.
//
// Every protocol owns one file that exports one rule set; the sets are
// registered into a single registry, which compiles all patterns once at
// start-up (plan.md §4.3).
package rules

import (
	"fmt"

	"hsxa-banner-fingerprint/internal/engine/rule"
)

// Builtin returns a fresh registry holding every compiled-in protocol set.
func Builtin() (*rule.Registry, error) {
	reg := rule.NewRegistry()
	for _, set := range allSets() {
		if err := reg.Register(set); err != nil {
			return nil, fmt.Errorf("register built-in rule set: %w", err)
		}
	}
	if err := reg.Compile(); err != nil {
		return nil, fmt.Errorf("compile built-in rules: %w", err)
	}
	return reg, nil
}

// allSets lists the built-in rule sets. The order also defines the metadata
// order reported by GET /api/v1/meta.
func allSets() []*rule.Set {
	return []*rule.Set{
		sshSet(),
		ftpSet(),
		smtpSet(),
		pop3Set(),
		imapSet(),
		telnetSet(),
		redisSet(),
		httpSet(),
		elasticsearchSet(),
		dockerAPISet(),
		mysqlSet(),
		postgresqlSet(),
		mongodbSet(),
		memcachedSet(),
		smbSet(),
		vncSet(),
		rdpSet(),
	}
}
