package report

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"secscantool/internal/model"
)

// Row is one flattened, report-ready finding: the same shape every output
// format (Markdown/HTML/PDF) renders as a table row, numbered once across
// the whole report so "S.No" means the same thing everywhere.
type Row struct {
	SNo           int
	Module        string
	Severity      model.Severity
	SeverityValue int
	RefID         string
	RefURL        string
	Issue         string
	Location      string // file:line for code findings, package@version (-> fixed) for dependency/container findings
	Description   string
	Tool          string
	FixSuggestion string
}

// ModuleGroup buckets a module's rows together, in report order.
type ModuleGroup struct {
	Title    string
	Language string
	Errors   []string
	Rows     []Row
}

// BuildGroups flattens a report into per-module row groups, each sorted
// worst-severity-first, with a single S.No sequence running across the
// entire report (so it reads as one master findings register).
func BuildGroups(r *model.Report) []ModuleGroup {
	var groups []ModuleGroup
	n := 0

	addModule := func(m model.ModuleResult) {
		title := m.Module
		if title == "" || title == "." {
			title = "(project root)"
		}
		findings := append([]model.Finding(nil), m.Findings...)
		sort.SliceStable(findings, func(i, j int) bool {
			return findings[i].Severity.Rank() > findings[j].Severity.Rank()
		})

		group := ModuleGroup{Title: title, Language: m.Language, Errors: m.Errors}
		for _, f := range findings {
			n++
			group.Rows = append(group.Rows, Row{
				SNo:           n,
				Module:        title,
				Severity:      f.Severity,
				SeverityValue: f.Severity.Rank(),
				RefID:         f.RefID,
				RefURL:        f.URL,
				Issue:         f.Title,
				Location:      locationOf(f),
				Description:   singleLine(f.Description),
				Tool:          f.Tool,
				FixSuggestion: f.FixSuggestion,
			})
		}
		groups = append(groups, group)
	}

	for _, m := range r.Modules {
		addModule(m)
	}
	if r.Container != nil {
		addModule(*r.Container)
	}
	return groups
}

func locationOf(f model.Finding) string {
	if f.File != "" {
		if f.Line > 0 {
			return fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		return f.File
	}
	if f.PackageName != "" {
		loc := f.PackageName
		if f.InstalledVersion != "" {
			loc += "@" + f.InstalledVersion
		}
		if f.FixedVersion != "" {
			loc += " -> " + f.FixedVersion
		}
		return loc
	}
	return "-"
}

var whitespaceRun = regexp.MustCompile(`\s+`)

// singleLine collapses a possibly multi-line, multi-space tool description
// into one clean line suitable for a table cell.
func singleLine(s string) string {
	return strings.TrimSpace(whitespaceRun.ReplaceAllString(s, " "))
}

// RiskStatement summarizes a severity breakdown as one stakeholder-facing
// sentence, for the top of a report.
func RiskStatement(s model.SeverityCounts) string {
	switch {
	case s.Critical > 0:
		return fmt.Sprintf("%d critical and %d high severity issue(s) require immediate attention.", s.Critical, s.High)
	case s.High > 0:
		return fmt.Sprintf("%d high severity issue(s) should be prioritized.", s.High)
	case s.Medium > 0:
		return fmt.Sprintf("No critical or high severity issues found; %d medium severity issue(s) are worth scheduling.", s.Medium)
	case s.Total() > 0:
		return "No critical, high, or medium severity issues found."
	default:
		return "No issues found — clean scan."
	}
}
