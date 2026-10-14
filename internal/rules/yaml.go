package rules

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"hsxa-banner-fingerprint/internal/engine/rule"
)

// OverlayFile is the schema of one external rule file (rules/*.yaml).
//
//	protocol: HTTP
//	ports: [80, 8080]
//	product_rules:
//	  - name: http-server-myapp
//	    match_type: regex
//	    pattern: '(?i)server:\s*myapp/([0-9.]+)'
//	    product: MyApp
//	    version_group: 1
//	    weight: 0.15
type OverlayFile struct {
	Protocol      string       `yaml:"protocol"`
	Ports         []int        `yaml:"ports"`
	ProtocolRules []*rule.Rule `yaml:"protocol_rules"`
	ProductRules  []*rule.Rule `yaml:"product_rules"`
}

// LoadOverlays merges every *.yaml file of dir into reg.
//
// A file whose protocol already exists extends the built-in set: rules with a
// known name replace the built-in rule, new names are appended. A file whose
// protocol is new adds a whole rule set. A missing directory is not an error,
// but an unreadable or invalid file is: start-up must fail loudly rather than
// serve with a half-applied overlay (plan.md §4.3).
func LoadOverlays(reg *rule.Registry, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read rules dir %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".yaml") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := mergeOverlayFile(reg, path); err != nil {
			return fmt.Errorf("load rule overlay %s: %w", path, err)
		}
	}
	if err := reg.Compile(); err != nil {
		return fmt.Errorf("compile rules after overlay %s: %w", dir, err)
	}
	return nil
}

func mergeOverlayFile(reg *rule.Registry, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var file OverlayFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	if strings.TrimSpace(file.Protocol) == "" {
		return errors.New("missing protocol")
	}
	base := reg.Set(file.Protocol)
	merged := &rule.Set{
		Protocol: file.Protocol,
		Ports:    file.Ports,
	}
	if base != nil {
		merged.Ports = append(append([]int{}, base.Ports...), file.Ports...)
		merged.ProtoRules = append(merged.ProtoRules, base.ProtoRules...)
		merged.ProductRules = append(merged.ProductRules, base.ProductRules...)
		merged.Extract = base.Extract
	}
	merged.ProtoRules = mergeRules(merged.ProtoRules, file.ProtocolRules)
	merged.ProductRules = mergeRules(merged.ProductRules, file.ProductRules)
	return reg.Replace(merged)
}

// mergeRules applies the "same name overrides, new name extends" overlay rule.
func mergeRules(base, overlay []*rule.Rule) []*rule.Rule {
	out := append([]*rule.Rule{}, base...)
	for _, incoming := range overlay {
		if incoming == nil {
			continue
		}
		replaced := false
		for i, existing := range out {
			if existing.Name == incoming.Name {
				out[i] = incoming
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, incoming)
		}
	}
	return out
}
