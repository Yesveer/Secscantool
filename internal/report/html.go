package report

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"

	"secscantool/internal/model"
)

const htmlHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Scan Report — %s</title>
<style>
  :root {
    color-scheme: light;
    --bg: #f4f5f7;
    --panel: #ffffff;
    --border: #e2e4e9;
    --text: #1f2430;
    --muted: #6b7280;
    --brand: #0e7490;
    --critical: #7f1d1d;
    --high: #b91c1c;
    --medium: #b45309;
    --low: #1d4ed8;
    --info: #4b5563;
    --row-alt: #f9fafb;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 2.5rem 1.5rem;
    line-height: 1.5;
  }
  .sheet { max-width: 1200px; margin: 0 auto; }
  header.title-block {
    background: linear-gradient(135deg, #0e7490, #155e75);
    color: #fff;
    border-radius: 14px;
    padding: 2rem 2.25rem;
    margin-bottom: 1.75rem;
  }
  header.title-block h1 { margin: 0 0 0.35rem; font-size: 1.7rem; letter-spacing: -0.02em; }
  header.title-block .subtitle { opacity: 0.85; font-size: 0.95rem; }
  .meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 0.75rem 2rem;
    margin-top: 1.25rem;
    font-size: 0.85rem;
  }
  .meta-grid dt { opacity: 0.75; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.04em; margin-bottom: 0.15rem; }
  .meta-grid dd { margin: 0; font-weight: 600; word-break: break-all; }

  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem 1.75rem;
    margin-bottom: 1.75rem;
  }
  .panel h2 { margin-top: 0; font-size: 1.15rem; }

  .summary-grid { display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1rem; }
  .stat {
    flex: 1; min-width: 100px;
    border-radius: 10px; padding: 0.9rem 0.5rem;
    text-align: center; color: #fff; font-weight: 700;
  }
  .stat .n { font-size: 1.6rem; line-height: 1.1; }
  .stat .label { font-size: 0.72rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.04em; opacity: 0.9; margin-top: 0.2rem; }
  .stat.CRITICAL { background: var(--critical); }
  .stat.HIGH { background: var(--high); }
  .stat.MEDIUM { background: var(--medium); }
  .stat.LOW { background: var(--low); }
  .stat.INFO { background: var(--info); }

  .risk-banner {
    border-radius: 8px;
    padding: 0.75rem 1rem;
    font-size: 0.92rem;
    font-weight: 600;
    background: #fff7ed;
    color: #9a3412;
    border: 1px solid #fed7aa;
  }
  .risk-banner.clean { background: #f0fdf4; color: #166534; border-color: #bbf7d0; }

  .module-header { display: flex; align-items: baseline; gap: 0.6rem; margin: 0 0 1rem; }
  .module-header h2 { margin: 0; font-size: 1.1rem; }
  .module-header .lang-tag {
    font-size: 0.7rem; font-weight: 700; text-transform: uppercase;
    background: #e0f2fe; color: #075985; padding: 0.15rem 0.55rem; border-radius: 999px;
  }
  .warn-line { color: #9a3412; background: #fff7ed; border: 1px solid #fed7aa; border-radius: 6px; padding: 0.5rem 0.75rem; font-size: 0.85rem; margin-bottom: 0.75rem; }
  .empty { color: var(--muted); font-style: italic; font-size: 0.9rem; }

  .table-scroll { overflow-x: auto; border: 1px solid var(--border); border-radius: 10px; }
  table.findings { width: 100%%; border-collapse: collapse; font-size: 0.82rem; min-width: 920px; }
  table.findings thead th {
    background: #0f172a; color: #fff; text-align: left;
    padding: 0.6rem 0.7rem; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.03em;
    position: sticky; top: 0;
  }
  table.findings tbody td { padding: 0.6rem 0.7rem; border-top: 1px solid var(--border); vertical-align: top; }
  table.findings tbody tr:nth-child(even) { background: var(--row-alt); }
  table.findings td.sno { color: var(--muted); font-variant-numeric: tabular-nums; width: 2.5rem; }
  table.findings td.loc, table.findings td.ref { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.78rem; white-space: nowrap; }
  table.findings td.issue { font-weight: 600; min-width: 180px; }
  table.findings td.desc { color: #374151; min-width: 220px; }
  table.findings td.fix { color: #047857; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.78rem; min-width: 200px; }
  a.ref-link { color: inherit; text-decoration: underline dotted; }

  .badge {
    display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px;
    font-size: 0.68rem; font-weight: 700; color: #fff; letter-spacing: 0.02em; white-space: nowrap;
  }
  .badge.CRITICAL { background: var(--critical); }
  .badge.HIGH { background: var(--high); }
  .badge.MEDIUM { background: var(--medium); }
  .badge.LOW { background: var(--low); }
  .badge.INFO { background: var(--info); }
  .sev-value { color: var(--muted); font-size: 0.72rem; margin-left: 0.3rem; }

  footer { text-align: center; color: var(--muted); font-size: 0.78rem; margin-top: 2rem; }

  @media print {
    body { background: #fff; padding: 0; }
    .panel, header.title-block { break-inside: avoid; }
  }
</style>
</head>
<body>
<div class="sheet">
`

// WriteHTML writes a standalone, offline-viewable HTML report to <dir>/report.html.
func WriteHTML(r *model.Report, dir string) (string, error) {
	var b strings.Builder

	fmt.Fprintf(&b, htmlHead, html.EscapeString(filepath.Base(r.ProjectPath)))

	fmt.Fprintf(&b, `<header class="title-block">`)
	fmt.Fprintf(&b, `<h1>Security Scan Report</h1>`)
	fmt.Fprintf(&b, `<div class="subtitle">Generated by secscantool</div>`)
	fmt.Fprintf(&b, `<dl class="meta-grid">`)
	fmt.Fprintf(&b, `<div><dt>Target</dt><dd>%s</dd></div>`, html.EscapeString(r.ProjectPath))
	fmt.Fprintf(&b, `<div><dt>Generated</dt><dd>%s</dd></div>`, r.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&b, `<div><dt>Total Findings</dt><dd>%d</dd></div>`, r.Summary.Total())
	fmt.Fprintf(&b, `</dl></header>`)

	writeHTMLSummary(&b, r.Summary)

	groups := BuildGroups(r)
	for _, g := range groups {
		writeHTMLGroup(&b, g)
	}

	if r.ContainerSkippedReason != "" {
		fmt.Fprintf(&b, `<section class="panel"><h2>Container Image Scan</h2><p class="warn-line">Skipped: %s</p></section>`,
			html.EscapeString(r.ContainerSkippedReason))
	}

	fmt.Fprintf(&b, `<footer>Generated by secscantool — deterministic, no AI/LLM involved</footer>`)
	fmt.Fprintf(&b, `</div></body></html>`)

	path := filepath.Join(dir, "report.html")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func writeHTMLSummary(b *strings.Builder, s model.SeverityCounts) {
	fmt.Fprintf(b, `<section class="panel"><h2>Executive Summary</h2><div class="summary-grid">`)
	cells := []struct {
		sev model.Severity
		n   int
	}{
		{model.SeverityCritical, s.Critical},
		{model.SeverityHigh, s.High},
		{model.SeverityMedium, s.Medium},
		{model.SeverityLow, s.Low},
		{model.SeverityInfo, s.Info},
	}
	for _, c := range cells {
		fmt.Fprintf(b, `<div class="stat %s"><div class="n">%d</div><div class="label">%s</div></div>`,
			c.sev, c.n, titleCase(string(c.sev)))
	}
	fmt.Fprintf(b, `</div>`)

	class := "risk-banner"
	if s.Critical == 0 && s.High == 0 && s.Medium == 0 {
		class += " clean"
	}
	fmt.Fprintf(b, `<div class="%s">%s</div>`, class, html.EscapeString(RiskStatement(s)))
	fmt.Fprintf(b, `</section>`)
}

func writeHTMLGroup(b *strings.Builder, g ModuleGroup) {
	fmt.Fprintf(b, `<section class="panel">`)
	fmt.Fprintf(b, `<div class="module-header"><h2>%s</h2>`, html.EscapeString(g.Title))
	if g.Language != "" {
		fmt.Fprintf(b, `<span class="lang-tag">%s</span>`, html.EscapeString(g.Language))
	}
	fmt.Fprintf(b, `</div>`)

	for _, e := range g.Errors {
		fmt.Fprintf(b, `<div class="warn-line">⚠️ %s</div>`, html.EscapeString(e))
	}

	if len(g.Rows) == 0 {
		fmt.Fprintf(b, `<p class="empty">No findings.</p></section>`)
		return
	}

	fmt.Fprintf(b, `<div class="table-scroll"><table class="findings"><thead><tr>`+
		`<th>#</th><th>Severity</th><th>CVE / Rule ID</th><th>Issue</th>`+
		`<th>Location / Package</th><th>Description</th><th>Fix Suggestion</th>`+
		`</tr></thead><tbody>`)

	for _, row := range g.Rows {
		fmt.Fprintf(b, `<tr>`)
		fmt.Fprintf(b, `<td class="sno">%d</td>`, row.SNo)
		fmt.Fprintf(b, `<td><span class="badge %s">%s</span><span class="sev-value">%d</span></td>`,
			row.Severity, row.Severity, row.SeverityValue)
		fmt.Fprintf(b, `<td class="ref">%s</td>`, refCell(row.RefID, row.RefURL))
		fmt.Fprintf(b, `<td class="issue">%s</td>`, html.EscapeString(orDash(row.Issue)))
		fmt.Fprintf(b, `<td class="loc">%s</td>`, html.EscapeString(orDash(row.Location)))
		fmt.Fprintf(b, `<td class="desc">%s</td>`, html.EscapeString(orDash(row.Description)))
		fmt.Fprintf(b, `<td class="fix">%s</td>`, html.EscapeString(orDash(row.FixSuggestion)))
		fmt.Fprintf(b, `</tr>`)
	}

	fmt.Fprintf(b, `</tbody></table></div></section>`)
}

func refCell(refID, refURL string) string {
	if refID == "" {
		return "-"
	}
	if refURL != "" {
		return fmt.Sprintf(`<a class="ref-link" href="%s" target="_blank" rel="noopener">%s</a>`,
			html.EscapeString(refURL), html.EscapeString(refID))
	}
	return html.EscapeString(refID)
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	lower := strings.ToLower(s)
	return strings.ToUpper(lower[:1]) + lower[1:]
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
