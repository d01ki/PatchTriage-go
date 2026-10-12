package pipeline

// Practicality evaluation: under the same review budget, how do
// severity-only (CVSS), probability-only (EPSS), observed-exploitation-first
// (KEV) and environment-specific SSVC orderings differ? SSVC may place a KEV
// finding behind a more urgent deployment decision; the comparison makes
// that tradeoff visible. It compares orderings on the supplied inventory and
// is not independent ground truth.

import (
	"sort"

	"github.com/d01ki/PatchTriage-go/internal/decision"
	"github.com/d01ki/PatchTriage-go/internal/model"
)

// EvalRow compares what each ordering surfaces within the top k findings.
type EvalRow struct {
	K               int     `json:"k"`
	KEVBaseline     int     `json:"kev_baseline"`
	KEVEPSS         int     `json:"kev_epss"`
	KEVKEV          int     `json:"kev_kev"`
	KEVSSVC         int     `json:"kev_ssvc"`
	KEVPatchTriage  int     `json:"kev_patchtriage"`
	KEVTotal        int     `json:"kev_total"`
	EPSSBaseline    float64 `json:"epss_baseline"`
	EPSSEPSS        float64 `json:"epss_epss"`
	EPSSKEV         float64 `json:"epss_kev"`
	EPSSSSVC        float64 `json:"epss_ssvc"`
	EPSSPatchTriage float64 `json:"epss_patchtriage"`
	EPSSTotal       float64 `json:"epss_total"`
	UrgentCVSS      int     `json:"urgent_cvss"`
	UrgentEPSS      int     `json:"urgent_epss"`
	UrgentKEV       int     `json:"urgent_kev"`
	UrgentSSVC      int     `json:"urgent_ssvc"`
	UrgentTotal     int     `json:"urgent_total"`
}

func epssOf(f *model.Finding) float64 {
	if f.Enrichment.EPSSScore == nil {
		return 0
	}
	return *f.Enrichment.EPSSScore
}

func cvssOf(f *model.Finding) float64 {
	if f.Enrichment.NVDCVSSScore != nil && *f.Enrichment.NVDCVSSScore != 0 {
		return *f.Enrichment.NVDCVSSScore
	}
	if f.CVSSScore != nil {
		return *f.CVSSScore
	}
	return 0
}

func isUrgent(f *model.Finding) bool {
	return f.Triage != nil && (f.Triage.Priority == "P1" || f.Triage.Priority == "P2")
}

// sortedBy returns a stable descending ordering by the key tuple.
func sortedBy(findings []*model.Finding, key func(*model.Finding) []float64) []*model.Finding {
	out := append([]*model.Finding(nil), findings...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := key(out[i]), key(out[j])
		for n := range a {
			if a[n] != b[n] {
				return a[n] > b[n]
			}
		}
		return false
	})
	return out
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func count(findings []*model.Finding, k int, match func(*model.Finding) bool) int {
	n := 0
	for _, f := range findings[:k] {
		if match(f) {
			n++
		}
	}
	return n
}

func epssMass(findings []*model.Finding) float64 {
	total := 0.0
	for _, f := range findings {
		total += epssOf(f)
	}
	return total
}

// Evaluate compares the four orderings at each review budget. With no
// budgets it uses n/4, n/2 and n.
func Evaluate(findings []*model.Finding, budgets []int) []EvalRow {
	if len(findings) == 0 {
		return []EvalRow{}
	}
	base := sortedBy(findings, func(f *model.Finding) []float64 { return []float64{cvssOf(f)} })
	epssOrder := sortedBy(findings, func(f *model.Finding) []float64 { return []float64{epssOf(f), cvssOf(f)} })
	kevOrder := sortedBy(findings, func(f *model.Finding) []float64 {
		return []float64{boolValue(f.Enrichment.InCISAKEV), epssOf(f), cvssOf(f)}
	})
	ssvcOrder := append([]*model.Finding(nil), findings...)
	sort.SliceStable(ssvcOrder, func(i, j int) bool { return decision.OrderLess(ssvcOrder[i], ssvcOrder[j]) })

	kev := func(f *model.Finding) bool { return f.Enrichment.InCISAKEV }
	n := len(findings)
	if len(budgets) == 0 {
		seen := map[int]bool{}
		for _, b := range []int{max(1, n/4), max(1, n/2), n} {
			if !seen[b] {
				seen[b] = true
				budgets = append(budgets, b)
			}
		}
		sort.Ints(budgets)
	}
	rows := make([]EvalRow, 0, len(budgets))
	for _, k := range budgets {
		k = min(k, n)
		rows = append(rows, EvalRow{
			K: k, KEVBaseline: count(base, k, kev), KEVEPSS: count(epssOrder, k, kev), KEVKEV: count(kevOrder, k, kev),
			KEVSSVC: count(ssvcOrder, k, kev), KEVPatchTriage: count(ssvcOrder, k, kev), KEVTotal: count(findings, n, kev),
			EPSSBaseline: pyRound(epssMass(base[:k]), 3), EPSSEPSS: pyRound(epssMass(epssOrder[:k]), 3),
			EPSSKEV: pyRound(epssMass(kevOrder[:k]), 3), EPSSSSVC: pyRound(epssMass(ssvcOrder[:k]), 3),
			EPSSPatchTriage: pyRound(epssMass(ssvcOrder[:k]), 3), EPSSTotal: pyRound(epssMass(findings), 3),
			UrgentCVSS: count(base, k, isUrgent), UrgentEPSS: count(epssOrder, k, isUrgent),
			UrgentKEV: count(kevOrder, k, isUrgent), UrgentSSVC: count(ssvcOrder, k, isUrgent),
			UrgentTotal: count(findings, n, isUrgent),
		})
	}
	return rows
}
