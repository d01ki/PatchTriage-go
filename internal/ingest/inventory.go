package ingest

// Organizational context. Scanners know nothing about your environment; an
// asset inventory (YAML, checked into your repository) supplies it:
//
//	assets:
//	  - match: "web-frontend*"        # fnmatch glob against the asset identifier
//	    criticality: critical
//	    internet_exposed: true
//	    system_exposure: open         # SSVC: small|controlled|open
//	    mission_impact: mef_failure   # SSVC organizational consequence
//	    safety_impact: critical
//
// The first matching rule applies.

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/d01ki/PatchTriage-go/internal/model"
)

// InventoryEntry is one rule of the asset inventory.
type InventoryEntry map[string]any

var contextChoiceFields = []string{
	"system_exposure", "automatable", "mission_impact", "safety_impact",
	"publicly_exposed", "bod2604_applicability",
}

// LoadInventory reads an asset inventory YAML file.
func LoadInventory(path string) ([]InventoryEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Assets []InventoryEntry `yaml:"assets"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, entry := range doc.Assets {
		if _, ok := entry["match"]; !ok {
			return nil, fmt.Errorf("inventory entry missing 'match': %v", map[string]any(entry))
		}
	}
	return doc.Assets, nil
}

// pyStr renders a YAML scalar like Python's str().
func pyStr(value any) string {
	switch v := value.(type) {
	case nil:
		return "None"
	case string:
		return v
	case bool:
		if v {
			return "True"
		}
		return "False"
	case float64:
		s := strconv.FormatFloat(v, 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s
	}
	return fmt.Sprint(value)
}

// yaml11Bools are the YAML 1.1 boolean spellings PyYAML resolves unquoted.
var yaml11Bools = map[string]bool{"true": true, "false": false, "yes": true, "no": false, "on": true, "off": false, "y": true, "n": false}

func asBool(value any, field string) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		if b, ok := yaml11Bools[strings.ToLower(strings.TrimSpace(v))]; ok {
			return b, nil
		}
	}
	return false, fmt.Errorf("inventory field '%s' must be true or false", field)
}

func isFalsy(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case bool:
		return !v
	case string:
		return v == ""
	case int:
		return v == 0
	case float64:
		return v == 0
	case []any:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	}
	return false
}

func asChoice(value any, field string) (string, error) {
	if b, ok := value.(bool); ok && (field == "automatable" || field == "publicly_exposed") {
		if b {
			return "yes", nil
		}
		return "no", nil
	}
	text := ""
	if !isFalsy(value) {
		text = pyStr(value)
	}
	normalized, err := model.NormalizeChoice(field, text)
	if err != nil {
		return "", fmt.Errorf("inventory field '%s' %s", field, strings.TrimPrefix(err.Error(), field+" "))
	}
	return normalized, nil
}

// fnmatch matches like Python's fnmatch.fnmatchcase: "*" also crosses "/".
func fnmatch(name, pattern string) bool {
	var b strings.Builder
	b.WriteString(`(?s)\A`)
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '[':
			j := i + 1
			if j < len(pattern) && pattern[j] == '!' {
				j++
			}
			if j < len(pattern) && pattern[j] == ']' {
				j++
			}
			for j < len(pattern) && pattern[j] != ']' {
				j++
			}
			if j >= len(pattern) {
				b.WriteString(`\[`)
				continue
			}
			class := pattern[i+1 : j]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			} else if strings.HasPrefix(class, "^") {
				class = `\` + class
			}
			b.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
			i = j
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(`\z`)
	re, err := regexp.Compile(b.String())
	return err == nil && re.MatchString(name)
}

// ApplyContext applies the first matching inventory rule to each finding's
// asset and returns how many findings matched.
func ApplyContext(findings []*model.Finding, inventory []InventoryEntry) (int, error) {
	matched := 0
	for _, f := range findings {
		for _, rule := range inventory {
			if !fnmatch(f.Asset.Identifier, pyStr(rule["match"])) {
				continue
			}
			if err := applyRule(&f.Asset, rule); err != nil {
				return matched, err
			}
			matched++
			break
		}
	}
	return matched, nil
}

func applyRule(a *model.Asset, rule InventoryEntry) error {
	if v, ok := rule["criticality"]; ok {
		a.Criticality = pyStr(v)
	}
	for field, target := range map[string]**bool{
		"internet_exposed": &a.InternetExposed, "reachable": &a.Reachable, "runtime_observed": &a.RuntimeObserved,
	} {
		if v, ok := rule[field]; ok {
			b, err := asBool(v, field)
			if err != nil {
				return err
			}
			*target = &b
		}
	}
	targets := map[string]*string{
		"system_exposure": &a.SystemExposure, "automatable": &a.Automatable,
		"mission_impact": &a.MissionImpact, "safety_impact": &a.SafetyImpact,
		"publicly_exposed": &a.PubliclyExposed, "bod2604_applicability": &a.BOD2604Applicability,
	}
	for _, field := range contextChoiceFields {
		v, ok := rule[field]
		if !ok {
			continue
		}
		value, err := asChoice(v, field)
		if err != nil {
			_, allowed := model.NormalizeChoice(field, "\x00")
			return fmt.Errorf("inventory field '%s' must be one of: %s", field,
				strings.TrimPrefix(allowed.Error(), field+" must be one of: "))
		}
		*targets[field] = value
	}
	if v, ok := rule["context_sources"]; ok {
		sources := []string{}
		switch s := v.(type) {
		case string:
			sources = []string{s}
		case []any:
			for _, item := range s {
				sources = append(sources, pyStr(item))
			}
		}
		a.ContextSources = sources
	}
	if v, ok := rule["owner"]; ok {
		a.Owner = pyStr(v)
	}
	if v, ok := rule["notes"]; ok {
		a.ContextNotes = pyStr(v)
	}
	return nil
}
