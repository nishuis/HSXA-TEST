package rule

import (
	"errors"
	"fmt"
)

// Registry is a compiled, read-only collection of protocol rule sets. It is
// built once during start-up and then shared by every request.
type Registry struct {
	sets    []*Set
	byProto map[string]*Set
	byPort  map[int][]*Set
	rules   int
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		byProto: make(map[string]*Set),
		byPort:  make(map[int][]*Set),
	}
}

// Register adds a rule set. Registering two sets for the same protocol is an
// error, so a typo cannot silently shadow a protocol.
func (r *Registry) Register(s *Set) error {
	if s == nil {
		return errors.New("rule: cannot register a nil rule set")
	}
	if s.Protocol == "" {
		return errors.New("rule: rule set without a protocol name")
	}
	if _, dup := r.byProto[s.Protocol]; dup {
		return fmt.Errorf("rule: duplicate protocol %q", s.Protocol)
	}
	r.sets = append(r.sets, s)
	r.byProto[s.Protocol] = s
	return nil
}

// Replace registers a set, overriding a previously registered set with the
// same protocol. It backs the external YAML overlay rule "external overrides
// built-in" (plan.md §4.3).
func (r *Registry) Replace(s *Set) error {
	if s == nil {
		return errors.New("rule: cannot register a nil rule set")
	}
	if s.Protocol == "" {
		return errors.New("rule: rule set without a protocol name")
	}
	if old, ok := r.byProto[s.Protocol]; ok {
		for i, existing := range r.sets {
			if existing == old {
				r.sets[i] = s
				break
			}
		}
	} else {
		r.sets = append(r.sets, s)
	}
	r.byProto[s.Protocol] = s
	return nil
}

// Compile compiles every registered set and rebuilds the derived indexes. It
// must be called once after registration and before the registry is used.
func (r *Registry) Compile() error {
	for _, s := range r.sets {
		if err := s.Compile(); err != nil {
			return err
		}
	}
	r.byPort = make(map[int][]*Set, len(r.byPort))
	r.rules = 0
	for _, s := range r.sets {
		r.rules += s.RuleCount()
		for _, p := range s.Ports {
			r.byPort[p] = append(r.byPort[p], s)
		}
	}
	return nil
}

// Set returns the rule set of a protocol, or nil when the protocol is unknown.
func (r *Registry) Set(protocol string) *Set {
	return r.byProto[protocol]
}

// Sets returns the registered sets in registration order.
func (r *Registry) Sets() []*Set { return r.sets }

// Protocols lists the registered protocol names in registration order.
func (r *Registry) Protocols() []string {
	out := make([]string, 0, len(r.sets))
	for _, s := range r.sets {
		out = append(out, s.Protocol)
	}
	return out
}

// RuleCount returns the number of compiled rules across every set.
func (r *Registry) RuleCount() int {
	if r.rules != 0 {
		return r.rules
	}
	n := 0
	for _, s := range r.sets {
		n += s.RuleCount()
	}
	return n
}

// ByPort returns the rule sets whose port prior includes port, in
// registration order.
func (r *Registry) ByPort(port int) []*Set { return r.byPort[port] }

// MatchSignature reports the first protocol rule of each set that fires on in.
// The result is ordered by registry registration order; callers rank it.
func (r *Registry) MatchSignature(in Input) []RuleMatch {
	var out []RuleMatch
	for _, s := range r.sets {
		if rule, groups, ok := s.Signature(in); ok {
			out = append(out, RuleMatch{Protocol: s.Protocol, Rule: rule, Groups: groups})
		}
	}
	return out
}

// RuleMatch pairs a fired protocol rule with its protocol and captures.
type RuleMatch struct {
	Protocol string
	Rule     *Rule
	Groups   []string
}
