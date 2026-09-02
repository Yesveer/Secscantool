// Package model defines the shared data types every scanner adapter and
// report writer speaks, so the core engine never depends on any single
// tool's native output format.
package model

import "time"

// Severity is a normalized severity level, independent of which underlying
// tool produced the finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Rank returns a numeric weight so findings can be sorted worst-first.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	default:
		return 1
	}
}

// Stage identifies which phase of the pipeline produced a finding.
type Stage string

const (
	StageCode       Stage = "code"
	StageDependency Stage = "dependency"
	StageContainer  Stage = "container"
)

// Finding is one normalized vulnerability/issue, regardless of source tool.
type Finding struct {
	Tool  string `json:"tool"`
	Stage Stage  `json:"stage"`
	// RefID is the finding's own identifier: a CVE/GHSA/OSV id for
	// dependency and container findings, or the scanner's own rule id
	// (e.g. gosec's "G204", semgrep's check_id) for code findings. Kept
	// separate from Title so reports can show it as its own column.
	RefID       string   `json:"ref_id,omitempty"`
	Language    string   `json:"language,omitempty"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	File        string   `json:"file,omitempty"`
	Line        int      `json:"line,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	// URL links to the advisory or rule documentation, when the
	// underlying tool provides one.
	URL              string `json:"url,omitempty"`
	PackageName      string `json:"package_name,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`
	FixedVersion     string `json:"fixed_version,omitempty"`
	FixSuggestion    string `json:"fix_suggestion,omitempty"`
}

// ModuleResult holds every finding + execution error for one detected
// project module (a directory containing a go.mod or package.json, etc).
type ModuleResult struct {
	Module   string    `json:"module"`
	Language string    `json:"language"`
	Findings []Finding `json:"findings"`
	Errors   []string  `json:"errors,omitempty"`
}

// SeverityCounts tallies findings by severity for quick summaries.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Add increments the counter matching sev.
func (c *SeverityCounts) Add(sev Severity) {
	switch sev {
	case SeverityCritical:
		c.Critical++
	case SeverityHigh:
		c.High++
	case SeverityMedium:
		c.Medium++
	case SeverityLow:
		c.Low++
	default:
		c.Info++
	}
}

// Total returns the sum of every severity bucket.
func (c SeverityCounts) Total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Info
}

// Report is the final aggregated result of a full scan run.
type Report struct {
	ProjectPath            string         `json:"project_path"`
	GeneratedAt            time.Time      `json:"generated_at"`
	Modules                []ModuleResult `json:"modules"`
	Container              *ModuleResult  `json:"container,omitempty"`
	ContainerSkippedReason string         `json:"container_skipped_reason,omitempty"`
	Summary                SeverityCounts `json:"summary"`
}

// AllFindings flattens every module + the container result into one slice,
// sorted worst-severity-first.
func (r *Report) AllFindings() []Finding {
	var all []Finding
	for _, m := range r.Modules {
		all = append(all, m.Findings...)
	}
	if r.Container != nil {
		all = append(all, r.Container.Findings...)
	}
	return all
}

// ComputeSummary recalculates r.Summary from every finding currently in the report.
func (r *Report) ComputeSummary() {
	var counts SeverityCounts
	for _, f := range r.AllFindings() {
		counts.Add(f.Severity)
	}
	r.Summary = counts
}
