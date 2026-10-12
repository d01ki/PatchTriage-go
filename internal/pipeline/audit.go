// Package pipeline runs the assessment pipeline and the layers after the
// decision: machine audit, remediation plan, ordering evaluation and the
// human-facing presentation of results.
package pipeline

// Triage audit: every decision record is machine-checked against the
// deterministic signals. The audit detects structured decision conflicts,
// unsupported numeric claims and unsafe remediation; it is a review control,
// not a proof that arbitrary prose is correct. Checks per finding:
//
//	fabricated_numbers    numeric and percentage claims must match real
//	                      signals or the deterministic service target
//	ssvc_consistency      priority and outcome must match the Deployer table
//	fix_consistency       patch_* needs a fixed version; mitigate is for none
//	evidence_completeness the SSVC path and point provenance must be present
//
// AI recommendation checks are added with the AI backends (phase 2).

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/d01ki/PatchTriage-go/internal/decision"
	"github.com/d01ki/PatchTriage-go/internal/model"
)

var (
	numberPattern   = regexp.MustCompile(`(\d+(?:\.\d+)?)(\s*%)?`)
	urlPattern      = regexp.MustCompile(`(?i)https?://\S+`)
	datePattern     = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`)
	cvePattern      = regexp.MustCompile(`CVE-\d{4}-\d+`)
	durationPattern = regexp.MustCompile(`\b(?:day|days|hour|hours|week|weeks|month|months|deadline|sla|target)\b`)
	percentPattern  = regexp.MustCompile(`\b(?:percent|percentage|percentile)\b`)
	signalPattern   = regexp.MustCompile(`\b(?:epss|cvss|score|percentile|probability|risk\s+rating)\b`)
)

var auditChecks = []string{"fabricated_numbers", "ssvc_consistency", "fix_consistency",
	"evidence_completeness", "ai_recommendation_consistency"}

// pyRound rounds like Python's round(x, n): correctly rounded decimal.
func pyRound(x float64, n int) float64 {
	v, _ := strconv.ParseFloat(strconv.FormatFloat(x, 'f', n, 64), 64)
	return v
}

func signalValues(f *model.Finding) []float64 {
	e := f.Enrichment
	var out []float64
	for _, v := range []*float64{e.EPSSScore, e.EPSSPercentile, e.NVDCVSSScore, f.CVSSScore} {
		if v != nil {
			out = append(out, *v, pyRound(*v, 1), pyRound(*v, 2))
		}
	}
	return out
}

func percentageValues(f *model.Finding) []float64 {
	var out []float64
	for _, v := range []*float64{f.Enrichment.EPSSScore, f.Enrichment.EPSSPercentile} {
		if v == nil {
			continue
		}
		p := *v
		if p >= 0 && p <= 1 {
			p *= 100
		}
		out = append(out, p, math.RoundToEven(p), pyRound(p, 1), pyRound(p, 2))
	}
	return out
}

// stripKnownTokens removes URLs, dates, CVE ids and version strings so they
// are not read as numeric claims.
func stripKnownTokens(f *model.Finding, text string) string {
	text = urlPattern.ReplaceAllString(text, " ")
	text = datePattern.ReplaceAllString(text, " ")
	text = cvePattern.ReplaceAllString(text, " ")
	tokens := append([]string{f.VulnID}, f.Aliases...)
	tokens = append(tokens, f.Package.Version, f.Package.FixedVersion, f.Enrichment.NVDCVSSVector, f.Enrichment.NVDCVSSVersion)
	if f.Enrichment.KEVDueDate != nil {
		tokens = append(tokens, *f.Enrichment.KEVDueDate)
	}
	for _, token := range tokens {
		if token != "" {
			text = strings.ReplaceAll(text, token, " ")
		}
	}
	return text
}

func isWordChar(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func near(values []float64, value float64) bool {
	for _, known := range values {
		if math.Abs(value-known) <= 0.051 {
			return true
		}
	}
	return false
}

func numericClaimFlags(f *model.Finding, field, text string, deadlineDays int) []string {
	stripped := stripKnownTokens(f, text)
	signals, percentages := signalValues(f), percentageValues(f)
	var flags []string
	for pos := 0; pos <= len(stripped); {
		loc := numberPattern.FindStringSubmatchIndex(stripped[pos:])
		if loc == nil {
			break
		}
		base := pos
		start, end := base+loc[0], base+loc[1]
		// Emulate Python's (?<![A-Za-z0-9_]) lookbehind: retry one later.
		if start > 0 && isWordChar(stripped[start-1]) {
			pos = start + 1
			continue
		}
		pos = end
		rendered := stripped[base+loc[2] : base+loc[3]]
		value, _ := strconv.ParseFloat(rendered, 64)
		isPercent := loc[4] >= 0
		nearby := strings.ToLower(stripped[max(0, start-18):min(len(stripped), end+18)])
		isDuration := durationPattern.MatchString(nearby)
		isPercentageContext := isPercent || percentPattern.MatchString(nearby)
		signalContext := signalPattern.MatchString(nearby)
		// Ordinals, protocol versions, step numbers and other bare prose
		// numbers are not quantitative vulnerability claims.
		if !(isPercentageContext || isDuration || signalContext) {
			continue
		}
		var allowed []float64
		switch {
		case isPercent:
			allowed = percentages
		case isPercentageContext:
			allowed = append(append([]float64{}, percentages...), signals...)
		case isDuration:
			allowed = []float64{float64(deadlineDays)}
		default:
			allowed = signals
		}
		if near(allowed, value) {
			continue
		}
		if isPercent {
			flags = append(flags, fmt.Sprintf("fabricated_percentage:%s:%s%%", field, rendered))
		} else {
			flags = append(flags, fmt.Sprintf("fabricated_number:%s:%s", field, rendered))
		}
	}
	return flags
}

// AuditFinding checks one finding's decision record against a fresh
// deterministic baseline.
func AuditFinding(f *model.Finding) map[string]any {
	t := f.Triage
	if t == nil {
		t = &model.Triage{}
	}
	baseline := decision.Triage(f)
	flags := []string{}
	if t.Rationale != "" {
		flags = append(flags, numericClaimFlags(f, "rationale", t.Rationale, baseline.SuggestedDeadlineDays)...)
	}
	if t.Priority != baseline.Priority {
		flags = append(flags, fmt.Sprintf("ssvc_priority_mismatch:%s->%s", baseline.Priority, t.Priority))
	}
	if t.Action != baseline.Action {
		flags = append(flags, fmt.Sprintf("ssvc_action_mismatch:%s->%s", baseline.Action, t.Action))
	}
	if t.SuggestedDeadlineDays != baseline.SuggestedDeadlineDays {
		flags = append(flags, fmt.Sprintf("ssvc_deadline_mismatch:%d->%d", baseline.SuggestedDeadlineDays, t.SuggestedDeadlineDays))
	}
	expected := baseline.SSVC
	if actual := t.SSVC; actual == nil {
		flags = append(flags, "ssvc_missing")
	} else {
		if actual.Model != expected.Model {
			flags = append(flags, "ssvc_model_mismatch")
		}
		if actual.Decision != expected.Decision {
			flags = append(flags, fmt.Sprintf("ssvc_decision_mismatch:%s->%s", expected.Decision, actual.Decision))
		}
		if actual.DecisionPath != expected.DecisionPath {
			flags = append(flags, "ssvc_path_mismatch")
		}
		for _, p := range []struct {
			key              string
			actual, expected model.DecisionPoint
		}{
			{"exploitation", actual.Exploitation, expected.Exploitation},
			{"system_exposure", actual.SystemExposure, expected.SystemExposure},
			{"automatable", actual.Automatable, expected.Automatable},
			{"mission_impact", actual.MissionImpact, expected.MissionImpact},
			{"safety_impact", actual.SafetyImpact, expected.SafetyImpact},
			{"human_impact", actual.HumanImpact, expected.HumanImpact},
		} {
			if p.actual.Value != p.expected.Value {
				flags = append(flags, "ssvc_input_mismatch:"+p.key)
			}
			if p.actual.Source == "" || p.actual.Confidence == "" {
				flags = append(flags, "ssvc_evidence_missing:"+p.key)
			}
		}
	}
	hasFix := f.Package.FixedVersion != ""
	if strings.HasPrefix(t.Action, "patch") && !hasFix {
		flags = append(flags, "patch_without_fix")
	}
	if t.Action == "mitigate" && hasFix && (t.Priority == "P1" || t.Priority == "P2") {
		flags = append(flags, "mitigate_despite_available_fix")
	}
	return map[string]any{
		"verified": len(flags) == 0, "flags": flags, "baseline_priority": baseline.Priority,
		"ssvc_decision": expected.Decision, "checks": auditChecks,
	}
}

// FlaggedFinding names a finding whose decision record failed the audit.
type FlaggedFinding struct {
	VulnID string
	Flags  []string
}

// AuditSummary counts audited and verified decision records.
type AuditSummary struct {
	Total, Verified int
	Flagged         []FlaggedFinding
}

// AuditAll audits every triaged finding in place.
func AuditAll(findings []*model.Finding) AuditSummary {
	var s AuditSummary
	for _, f := range findings {
		if f.Triage == nil {
			continue
		}
		result := AuditFinding(f)
		f.Triage.Audit = result
		s.Total++
		if result["verified"] == true {
			s.Verified++
		} else {
			s.Flagged = append(s.Flagged, FlaggedFinding{f.VulnID, result["flags"].([]string)})
		}
	}
	return s
}
