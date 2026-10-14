// Package rule defines the declarative matching model shared by the built-in
// rule sets and the optional external YAML overlays.
//
// A rule is data: a match mode, a pattern, the evidence it contributes and a
// weight. Patterns are compiled once at start-up, so matching is allocation
// free and free of catastrophic backtracking (Go RE2).
package rule

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"hsxa-banner-fingerprint/internal/engine/decode"
)

// MatchType selects how a Rule pattern is compared against a payload.
type MatchType string

const (
	// MatchPrefix matches a literal byte prefix.
	MatchPrefix MatchType = "prefix"
	// MatchContains matches a literal byte substring.
	MatchContains MatchType = "contains"
	// MatchRegex matches a Go RE2 regular expression.
	MatchRegex MatchType = "regex"
	// MatchBinary matches a literal byte pattern at Offset.
	MatchBinary MatchType = "binary"
)

// Kind distinguishes protocol signature rules from product rules.
type Kind string

const (
	// KindProtocol marks a rule that identifies the protocol itself.
	KindProtocol Kind = "protocol"
	// KindProduct marks a rule that identifies a product inside a protocol.
	KindProduct Kind = "product"
)

// Default weights applied when a rule does not declare one. They mirror
// score.WeightProtoSignature and score.WeightProductStrong; every built-in
// rule sets its weight explicitly, so these defaults only serve external
// YAML overlay authors.
const (
	DefaultProtocolWeight = 0.60
	DefaultProductWeight  = 0.15
)

// Input is the normalised payload a rule is matched against.
type Input struct {
	Bytes []byte
	Port  int
}

// Text returns the payload as a Go string. Arbitrary bytes are preserved, so
// binary handshakes can be matched with plain string searches.
func (in Input) Text() string { return string(in.Bytes) }

// Findings is the product/version/os evidence contributed by a rule or by a
// bespoke extractor.
type Findings struct {
	Product string
	Version string
	OSHint  string
	Rule    string
	Weight  float64
	Signals []string
}

// Rule is one declarative matcher.
type Rule struct {
	Name      string    `yaml:"name"`
	Protocol  string    `yaml:"protocol"`
	Kind      Kind      `yaml:"kind"`
	MatchType MatchType `yaml:"match_type"`
	Pattern   string    `yaml:"pattern"`
	// Offset is the byte offset used by MatchBinary.
	Offset int `yaml:"offset"`
	// Product is the canonical product name contributed on match.
	Product string `yaml:"product"`
	// VersionGroup is the 1-based regex capture group holding the version.
	VersionGroup int `yaml:"version_group"`
	// VersionTemplate is a literal or $n template used when VersionGroup is 0.
	VersionTemplate string `yaml:"version_template"`
	// OSGroup is the 1-based regex capture group holding the OS hint.
	OSGroup int `yaml:"os_group"`
	// OSHint is a literal OS hint contributed on match.
	OSHint string `yaml:"os_hint"`
	// Weight is the confidence contribution; 0 selects the kind default.
	Weight float64 `yaml:"weight"`
	// Priority orders rules inside a set: higher runs first.
	Priority int `yaml:"priority"`

	compiled bool
	literal  []byte
	re       *regexp.Regexp
}

// Compile validates the rule and pre-compiles its regexp. It is idempotent.
func (r *Rule) Compile() error {
	switch r.Kind {
	case KindProtocol, KindProduct:
	default:
		return fmt.Errorf("rule %q: unknown kind %q", r.Name, r.Kind)
	}
	if r.Pattern == "" {
		return fmt.Errorf("rule %q: empty pattern", r.Name)
	}
	if r.compiled {
		return nil
	}
	switch r.MatchType {
	case MatchPrefix, MatchContains, MatchBinary:
		r.literal = decode.Unescape(r.Pattern)
		if len(r.literal) == 0 {
			return fmt.Errorf("rule %q: empty literal pattern", r.Name)
		}
	case MatchRegex:
		if err := checkByteEscapes(r.Pattern); err != nil {
			return fmt.Errorf("rule %q: %w", r.Name, err)
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return fmt.Errorf("rule %q: compile regex: %w", r.Name, err)
		}
		r.re = re
	case "":
		return fmt.Errorf("rule %q: missing match_type", r.Name)
	default:
		return fmt.Errorf("rule %q: unknown match_type %q", r.Name, r.MatchType)
	}
	if r.MatchType == MatchBinary && r.Offset < 0 {
		return fmt.Errorf("rule %q: negative offset", r.Name)
	}
	r.compiled = true
	return nil
}

// Match reports whether the rule fires on in. For regex rules the returned
// groups hold the capture groups, with groups[0] being the whole match.
func (r *Rule) Match(in Input) (groups []string, matched bool) {
	switch r.MatchType {
	case MatchRegex:
		if r.re == nil {
			return nil, false
		}
		m := r.re.FindSubmatch(in.Bytes)
		if m == nil {
			return nil, false
		}
		groups = make([]string, len(m))
		for i := range m {
			groups[i] = string(m[i])
		}
		return groups, true
	case MatchPrefix:
		if len(r.literal) == 0 {
			return nil, false
		}
		return nil, bytes.HasPrefix(in.Bytes, r.literal)
	case MatchContains:
		if len(r.literal) == 0 {
			return nil, false
		}
		return nil, bytes.Contains(in.Bytes, r.literal)
	case MatchBinary:
		if len(r.literal) == 0 || r.Offset < 0 || r.Offset > len(in.Bytes) {
			return nil, false
		}
		return nil, bytes.HasPrefix(in.Bytes[r.Offset:], r.literal)
	}
	return nil, false
}

// EffectiveWeight returns the confidence contribution of the rule, applying
// the kind default when Weight is unset.
func (r *Rule) EffectiveWeight() float64 {
	if r.Weight > 0 {
		return r.Weight
	}
	if r.Kind == KindProtocol {
		return DefaultProtocolWeight
	}
	return DefaultProductWeight
}

// ResolveVersion renders the version evidence from regex capture groups,
// honouring VersionGroup and VersionTemplate.
func (r *Rule) ResolveVersion(groups []string) string {
	if r.VersionGroup > 0 && r.VersionGroup < len(groups) {
		return groups[r.VersionGroup]
	}
	if r.VersionTemplate != "" {
		return ExpandTemplate(r.VersionTemplate, groups)
	}
	return ""
}

// ResolveOS renders the OS evidence from regex capture groups.
func (r *Rule) ResolveOS(groups []string) string {
	if r.OSGroup > 0 && r.OSGroup < len(groups) {
		return groups[r.OSGroup]
	}
	return ""
}

// FindingsFor builds the evidence the rule contributes on a match.
func (r *Rule) FindingsFor(groups []string) Findings {
	os := r.ResolveOS(groups)
	if os == "" {
		os = r.OSHint
	}
	return Findings{
		Product: r.Product,
		Version: r.ResolveVersion(groups),
		OSHint:  os,
		Rule:    r.Name,
		Weight:  r.EffectiveWeight(),
	}
}

// ExpandTemplate substitutes $1..$9 with the matching capture group; unknown
// references collapse to the empty string.
func ExpandTemplate(tmpl string, groups []string) string {
	if !strings.ContainsRune(tmpl, '$') {
		return tmpl
	}
	var b strings.Builder
	for i := 0; i < len(tmpl); i++ {
		if tmpl[i] == '$' && i+1 < len(tmpl) && tmpl[i+1] >= '0' && tmpl[i+1] <= '9' {
			idx := int(tmpl[i+1] - '0')
			if idx < len(groups) {
				b.WriteString(groups[idx])
			}
			i++
			continue
		}
		b.WriteByte(tmpl[i])
	}
	return b.String()
}

// checkByteEscapes rejects regex escapes for bytes at or above 0x80.
//
// Go regular expressions match runes over a UTF-8 interpretation of the
// payload, so "\xd0" looks for the two byte encoding of U+00D0 rather than for
// the raw byte 0xd0 and can never match a binary handshake. Byte-oriented
// signatures must use MatchBinary or MatchContains, which compare raw bytes.
func checkByteEscapes(pattern string) error {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '\\' {
			continue
		}
		if i+1 >= len(pattern) {
			break
		}
		switch pattern[i+1] {
		case '\\':
			i++
		case 'x':
			value, width, ok := parseHexEscape(pattern[i+2:])
			if !ok {
				continue
			}
			if value >= 0x80 {
				return fmt.Errorf(
					"regex escape %s matches rune U+%04X, not the raw byte; use match_type binary or contains for byte-oriented signatures",
					pattern[i:i+2+width], value,
				)
			}
			i += 1 + width
		}
	}
	return nil
}

// parseHexEscape parses the \xHH or \x{HHHH} body of an escape and reports how
// many bytes it spans inside rest.
func parseHexEscape(rest string) (value, width int, ok bool) {
	if rest == "" {
		return 0, 0, false
	}
	if rest[0] == '{' {
		end := strings.IndexByte(rest, '}')
		if end <= 1 {
			return 0, 0, false
		}
		v, err := strconv.ParseUint(rest[1:end], 16, 32)
		if err != nil {
			return 0, 0, false
		}
		return int(v), end + 1, true
	}
	if len(rest) < 2 {
		return 0, 0, false
	}
	v, err := strconv.ParseUint(rest[:2], 16, 16)
	if err != nil {
		return 0, 0, false
	}
	return int(v), 2, true
}

// Set is the rule collection of a single protocol: its signature rules, its
// product rules, its port priors and an optional bespoke extractor for binary
// handshakes that plain pattern matching cannot express.
type Set struct {
	Protocol     string
	Ports        []int
	ProtoRules   []*Rule
	ProductRules []*Rule
	Extract      ExtractFunc
}

// ExtractFunc resolves product evidence with protocol-specific logic.
type ExtractFunc func(in Input) (Findings, bool)

// Compile validates the set, compiles every pattern and sorts both rule lists
// by descending priority, keeping declaration order for equal priorities.
func (s *Set) Compile() error {
	if s.Protocol == "" {
		return fmt.Errorf("rule set: empty protocol")
	}
	for _, group := range []struct {
		label string
		rules []*Rule
	}{
		{"protocol", s.ProtoRules},
		{"product", s.ProductRules},
	} {
		seen := make(map[string]bool, len(group.rules))
		for _, r := range group.rules {
			if r.Name == "" {
				return fmt.Errorf("rule set %s: unnamed %s rule", s.Protocol, group.label)
			}
			if seen[r.Name] {
				return fmt.Errorf("rule set %s: duplicate %s rule %q", s.Protocol, group.label, r.Name)
			}
			seen[r.Name] = true
			if r.Protocol == "" {
				r.Protocol = s.Protocol
			}
			if r.Kind == "" {
				if group.label == "protocol" {
					r.Kind = KindProtocol
				} else {
					r.Kind = KindProduct
				}
			}
			if err := r.Compile(); err != nil {
				return err
			}
		}
		rules := group.rules
		sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority > rules[j].Priority })
	}
	return nil
}

// Signature returns the first protocol rule of the set that fires on in.
func (s *Set) Signature(in Input) (*Rule, []string, bool) {
	for _, r := range s.ProtoRules {
		if groups, ok := r.Match(in); ok {
			return r, groups, true
		}
	}
	return nil, nil, false
}

// Product returns the findings of the first product rule that fires on in;
// when no declarative rule matches it defers to the bespoke extractor.
func (s *Set) Product(in Input) (Findings, bool) {
	for _, r := range s.ProductRules {
		if groups, ok := r.Match(in); ok {
			return r.FindingsFor(groups), true
		}
	}
	if s.Extract != nil {
		if f, ok := s.Extract(in); ok {
			if f.Weight == 0 {
				f.Weight = DefaultProductWeight
			}
			return f, true
		}
	}
	return Findings{}, false
}

// RuleCount returns the number of rules in the set.
func (s *Set) RuleCount() int { return len(s.ProtoRules) + len(s.ProductRules) }
