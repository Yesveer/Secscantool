package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"secscantool/internal/model"
)

// WriteMarkdown writes a table-based report to <dir>/report.md: an
// executive summary, then one findings table per module, numbered as a
// single sequence across the whole report.
func WriteMarkdown(r *model.Report, dir string) (string, error) {
	var b strings.Builder

	fmt.Fprintf(&b, "# Security Scan Report\n\n")
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| **Target** | `%s` |\n", r.ProjectPath)
	fmt.Fprintf(&b, "| **Generated** | %s |\n", r.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&b, "| **Total findings** | %d |\n\n", r.Summary.Total())

	fmt.Fprintf(&b, "## Executive Summary\n\n")
	fmt.Fprintf(&b, "| Critical | High | Medium | Low | Info |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d | %d |\n\n",
		r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info)
	fmt.Fprintf(&b, "> %s\n\n", RiskStatement(r.Summary))

	groups := BuildGroups(r)
	for _, g := range groups {
		writeGroupTable(&b, g)
	}

	if r.ContainerSkippedReason != "" {
		fmt.Fprintf(&b, "## Container Image Scan\n\nSkipped: %s\n\n", r.ContainerSkippedReason)
	}

	path := filepath.Join(dir, "report.md")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func writeGroupTable(b *strings.Builder, g ModuleGroup) {
	fmt.Fprintf(b, "## %s", g.Title)
	if g.Language != "" {
		fmt.Fprintf(b, " (%s)", g.Language)
	}
	fmt.Fprintf(b, "\n\n")

	for _, e := range g.Errors {
		fmt.Fprintf(b, "> ⚠️ %s\n\n", e)
	}

	if len(g.Rows) == 0 {
		fmt.Fprintf(b, "No findings.\n\n")
		return
	}

	fmt.Fprintf(b, "| # | Severity | CVE / Rule ID | Issue | Location / Package | Description | Fix Suggestion |\n")
	fmt.Fprintf(b, "|---|---|---|---|---|---|---|\n")
	for _, row := range g.Rows {
		refID := mdCell(row.RefID)
		if row.RefID != "" && row.RefURL != "" {
			refID = fmt.Sprintf("[%s](%s)", mdCell(row.RefID), row.RefURL)
		}
		fmt.Fprintf(b, "| %d | %s (%d) | %s | %s | %s | %s | %s |\n",
			row.SNo,
			row.Severity, row.SeverityValue,
			refID,
			mdCell(row.Issue),
			mdCell(row.Location),
			mdCell(row.Description),
			mdCell(row.FixSuggestion),
		)
	}
	fmt.Fprintf(b, "\n")
}

// mdCell escapes a value for safe embedding in a GitHub-flavored markdown
// table cell: no literal pipes or newlines, and a placeholder when empty.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return s
}
