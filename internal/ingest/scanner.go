// Package ingest turns scanner output and SBOMs into normalized findings,
// correlates them across scanners, and applies the asset inventory.
package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/d01ki/PatchTriage-go/internal/model"
)

// LoadResult is the findings plus source-coverage metadata.
type LoadResult struct {
	Findings []model.RawFinding
	Coverage model.Coverage
}

var scannerFormats = []string{"grype", "osv", "trivy"}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		return string(runes[:n])
	}
	return s
}

func head(values []string, n int) []string {
	if len(values) > n {
		return values[:n]
	}
	return values
}

// preferCVE canonicalizes on a CVE id when one exists among id+aliases.
func preferCVE(primary string, aliases []string) (string, []string) {
	ids := append([]string{primary}, aliases...)
	var cves []string
	for _, id := range ids {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			cves = append(cves, id)
		}
	}
	if len(cves) == 0 {
		return primary, sortedSet(aliases)
	}
	sort.Strings(cves)
	canonical := strings.ToUpper(cves[0])
	var rest []string
	for _, id := range ids {
		if strings.ToUpper(id) != canonical {
			rest = append(rest, id)
		}
	}
	return canonical, sortedSet(rest)
}

func sortedSet(values []string) []string {
	out := unique(values)
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

func scannerAsset(defaultAsset *model.Asset, identifier, kind string) model.Asset {
	if defaultAsset != nil {
		return *defaultAsset
	}
	asset := model.NewAsset(identifier)
	asset.Kind = kind
	return asset
}

func maxScore(current *float64, value float64) *float64 {
	if current == nil || value > *current {
		return &value
	}
	return current
}

// ---------------------------------------------------------------- Trivy

type trivyReport struct {
	ArtifactName *string `json:"ArtifactName"`
	ArtifactType *string `json:"ArtifactType"`
	Results      []struct {
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			PkgIdentifier    struct {
				PURL string `json:"PURL"`
			} `json:"PkgIdentifier"`
			Severity    string   `json:"Severity"`
			Title       string   `json:"Title"`
			Description string   `json:"Description"`
			References  []string `json:"References"`
			CVSS        map[string]struct {
				V3Score  *float64 `json:"V3Score"`
				V40Score *float64 `json:"V40Score"`
				V2Score  *float64 `json:"V2Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func orDefault(value *string, fallback string) string {
	if value == nil {
		return fallback
	}
	return *value
}

func parseTrivy(raw []byte, defaultAsset *model.Asset, now time.Time) ([]model.RawFinding, error) {
	var report trivyReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("invalid Trivy JSON: %w", err)
	}
	asset := scannerAsset(defaultAsset, orDefault(report.ArtifactName, "unknown"), orDefault(report.ArtifactType, "unknown"))
	var findings []model.RawFinding
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			vulnID, aliases := preferCVE(v.VulnerabilityID, nil)
			var cvss *float64
			for _, source := range v.CVSS {
				for _, score := range []*float64{source.V3Score, source.V40Score, source.V2Score} {
					if score != nil {
						cvss = maxScore(cvss, *score)
					}
				}
			}
			findings = append(findings, model.RawFinding{
				VulnID: vulnID, Aliases: aliases, SourceScanner: "trivy",
				Package: model.Package{Name: v.PkgName, Version: v.InstalledVersion,
					Purl: v.PkgIdentifier.PURL, Ecosystem: result.Type, FixedVersion: v.FixedVersion},
				Asset: asset, Severity: model.ParseSeverity(v.Severity), CVSSScore: cvss,
				Title: v.Title, Description: truncate(v.Description, 2000),
				References: head(v.References, 15), DetectedAt: now,
			})
		}
	}
	return findings, nil
}

// ---------------------------------------------------------------- Grype

type grypeCVSS []struct {
	Metrics struct {
		BaseScore *float64 `json:"baseScore"`
	} `json:"metrics"`
}

type grypeReport struct {
	Source struct {
		Type   *string         `json:"type"`
		Target json.RawMessage `json:"target"`
	} `json:"source"`
	Matches []struct {
		Vulnerability struct {
			ID          string    `json:"id"`
			Severity    string    `json:"severity"`
			Description string    `json:"description"`
			DataSource  string    `json:"dataSource"`
			CVSS        grypeCVSS `json:"cvss"`
			Fix         struct {
				Versions []string `json:"versions"`
			} `json:"fix"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			ID   string    `json:"id"`
			CVSS grypeCVSS `json:"cvss"`
		} `json:"relatedVulnerabilities"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Purl    string `json:"purl"`
			Type    string `json:"type"`
		} `json:"artifact"`
	} `json:"matches"`
}

// grypeTarget reads source.target, which is a string or an object.
func grypeTarget(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if text == "" {
			return "unknown"
		}
		return text
	}
	var target struct {
		UserInput string  `json:"userInput"`
		ImageID   *string `json:"imageID"`
	}
	if json.Unmarshal(raw, &target) == nil && bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		if target.UserInput != "" {
			return target.UserInput
		}
		return orDefault(target.ImageID, "unknown")
	}
	return "unknown"
}

func parseGrype(raw []byte, defaultAsset *model.Asset, now time.Time) ([]model.RawFinding, error) {
	var report grypeReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("invalid Grype JSON: %w", err)
	}
	asset := scannerAsset(defaultAsset, grypeTarget(report.Source.Target), orDefault(report.Source.Type, "unknown"))
	var findings []model.RawFinding
	for _, m := range report.Matches {
		v := m.Vulnerability
		var related []string
		scores := append(grypeCVSS{}, v.CVSS...)
		for _, r := range m.RelatedVulnerabilities {
			if r.ID != "" {
				related = append(related, r.ID)
			}
			scores = append(scores, r.CVSS...)
		}
		vulnID, aliases := preferCVE(v.ID, related)
		var cvss *float64
		for _, c := range scores {
			if c.Metrics.BaseScore != nil {
				cvss = maxScore(cvss, *c.Metrics.BaseScore)
			}
		}
		fixed := ""
		if len(v.Fix.Versions) > 0 {
			fixed = v.Fix.Versions[0]
		}
		references := []string{}
		if v.DataSource != "" {
			references = []string{v.DataSource}
		}
		findings = append(findings, model.RawFinding{
			VulnID: vulnID, Aliases: aliases, SourceScanner: "grype",
			Package: model.Package{Name: m.Artifact.Name, Version: m.Artifact.Version,
				Purl: m.Artifact.Purl, Ecosystem: m.Artifact.Type, FixedVersion: fixed},
			Asset: asset, Severity: model.ParseSeverity(v.Severity), CVSSScore: cvss,
			Description: truncate(v.Description, 2000), References: references, DetectedAt: now,
		})
	}
	return findings, nil
}

// ---------------------------------------------------------------- OSV-Scanner

type osvScannerReport struct {
	Results []struct {
		Source struct {
			Path *string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
				Purl      string `json:"purl"`
			} `json:"package"`
			Vulnerabilities []OSVVuln `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

func referenceURLs(v OSVVuln) []string {
	urls := []string{}
	for _, r := range v.References {
		urls = append(urls, r.URL)
	}
	return head(urls, 15)
}

func parseOSVScanner(raw []byte, defaultAsset *model.Asset, now time.Time) ([]model.RawFinding, error) {
	var report osvScannerReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("invalid osv-scanner JSON: %w", err)
	}
	var findings []model.RawFinding
	for _, result := range report.Results {
		asset := scannerAsset(defaultAsset, orDefault(result.Source.Path, "unknown"), "repository")
		for _, p := range result.Packages {
			pkg := model.Package{Name: p.Package.Name, Version: p.Package.Version,
				Ecosystem: strings.ToLower(p.Package.Ecosystem), Purl: p.Package.Purl}
			for _, v := range p.Vulnerabilities {
				vulnID, aliases := preferCVE(v.ID, v.Aliases)
				withFix := pkg
				withFix.FixedVersion = SelectOSVFixedVersion(v, pkg)
				findings = append(findings, model.RawFinding{
					VulnID: vulnID, Aliases: aliases, SourceScanner: "osv", Package: withFix,
					Asset: asset, Severity: model.SeverityUnknown, // NVD fills it in
					Title: v.Summary, Description: truncate(v.Details, 2000),
					References: referenceURLs(v), DetectedAt: now,
				})
			}
		}
	}
	return findings, nil
}

// SniffFormat makes a best-effort guess at which scanner produced the JSON.
func SniffFormat(raw []byte) string {
	fields, ok := objectFields(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")))
	if !ok {
		return ""
	}
	has := func(key string) bool { _, found := fields[key]; return found }
	if has("Results") && (has("ArtifactName") || has("SchemaVersion")) {
		return "trivy"
	}
	if has("matches") && has("descriptor") {
		return "grype"
	}
	var rows []json.RawMessage
	if json.Unmarshal(fields["results"], &rows) == nil && fields["results"] != nil {
		for _, row := range rows {
			rowFields, isObject := objectFields(row)
			if _, hasPackages := rowFields["packages"]; !isObject || !hasPackages {
				return ""
			}
		}
		return "osv"
	}
	return ""
}

// ParseScanner parses one scanner report. A non-nil asset replaces the
// asset the scanner describes.
func ParseScanner(raw []byte, format string, asset *model.Asset) ([]model.RawFinding, error) {
	now := time.Now().UTC()
	switch format {
	case "trivy":
		return parseTrivy(raw, asset, now)
	case "grype":
		return parseGrype(raw, asset, now)
	case "osv":
		return parseOSVScanner(raw, asset, now)
	}
	return nil, fmt.Errorf("unsupported scanner format %q", format)
}

func isScannerFormat(format string) bool {
	for _, f := range scannerFormats {
		if f == format {
			return true
		}
	}
	return false
}

// LoadFile loads scanner or SBOM evidence with explicit coverage metadata.
// Scanner JSON is parsed offline; SBOMs are resolved through OSV.dev.
func LoadFile(ctx context.Context, path, format string, asset *model.Asset, osv *OSVClient) (LoadResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return LoadResult{}, err
	}
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	if !json.Valid(raw) {
		return LoadResult{}, fmt.Errorf("%s is not valid JSON", path)
	}
	if !isScannerFormat(format) {
		kind := IsSBOM(raw)
		if format == "cyclonedx" || format == "spdx" {
			kind = format
		}
		if kind != "" {
			return loadSBOM(ctx, raw, path, asset, osv)
		}
	}
	if format == "" {
		format = SniffFormat(raw)
	}
	if !isScannerFormat(format) {
		return LoadResult{}, fmt.Errorf("Unrecognized format for %s. Expected Trivy/Grype/OSV scanner JSON "+
			"(one of ['grype', 'osv', 'trivy']) or a CycloneDX/SPDX SBOM. Pass fmt= to force a scanner format.", path)
	}
	findings, err := ParseScanner(raw, format, asset)
	if err != nil {
		return LoadResult{}, err
	}
	return LoadResult{Findings: findings, Coverage: model.Coverage{
		"source_type": "scanner:" + format, "complete": true,
		"records": len(findings), "errors": []string{},
	}}, nil
}
