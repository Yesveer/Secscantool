package report

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-pdf/fpdf"

	"secscantool/internal/model"
)

// Landscape table column widths (mm), summing to the usable page width
// (297mm page - 10mm margins each side = 277mm).
var pdfColWidths = []float64{8, 20, 30, 45, 45, 65, 64}

var pdfHeaders = []string{"#", "Severity", "CVE / Rule ID", "Issue", "Location / Package", "Description", "Fix Suggestion"}

const pdfLineHeight = 4.3
const pdfCellPad = 1.2

// severityColor returns the RGB fill color used for a severity badge.
func severityColor(s model.Severity) (int, int, int) {
	switch s {
	case model.SeverityCritical:
		return 127, 29, 29
	case model.SeverityHigh:
		return 185, 28, 28
	case model.SeverityMedium:
		return 180, 83, 9
	case model.SeverityLow:
		return 29, 78, 216
	default:
		return 75, 85, 99
	}
}

// WritePDF renders the report as a landscape, paginated table to
// <dir>/report.pdf — a printable snapshot of the same findings as the
// other report formats.
func WritePDF(r *model.Report, dir string) (string, error) {
	pdf := fpdf.New("L", "mm", "A4", "")
	pdf.SetMargins(10, 10, 10)
	pdf.SetAutoPageBreak(false, 10) // page breaks are handled manually per table row
	pdf.SetTitle("Security Scan Report", false)
	pdf.AddPage()

	// fpdf's core fonts (Helvetica) only support the single-byte cp1252
	// encoding, but scanner output (titles/descriptions/paths) is arbitrary
	// UTF-8 — every string drawn on the page must go through this
	// translator first, or non-ASCII bytes render as mojibake.
	tr := pdf.UnicodeTranslatorFromDescriptor("")

	drawHeader(pdf, tr, r)
	drawSummary(pdf, tr, r.Summary)

	for _, g := range BuildGroups(r) {
		drawGroup(pdf, tr, g)
	}

	if r.ContainerSkippedReason != "" {
		pdf.SetFont("Helvetica", "B", 12)
		pdf.CellFormat(0, 8, tr("Container Image Scan"), "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetTextColor(154, 52, 18)
		pdf.MultiCell(0, 5, tr("Skipped: "+r.ContainerSkippedReason), "", "L", false)
		pdf.SetTextColor(0, 0, 0)
	}

	path := filepath.Join(dir, "report.pdf")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := pdf.Output(f); err != nil {
		return "", err
	}
	return path, nil
}

func drawHeader(pdf *fpdf.Fpdf, tr func(string) string, r *model.Report) {
	pdf.SetFont("Helvetica", "B", 18)
	pdf.SetTextColor(14, 116, 144)
	pdf.CellFormat(0, 9, tr("Security Scan Report"), "", 1, "L", false, 0, "")
	pdf.SetTextColor(0, 0, 0)

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(100, 100, 100)
	pdf.CellFormat(0, 5, tr("Target: "+r.ProjectPath), "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 5, tr(fmt.Sprintf("Generated: %s   |   Total findings: %d",
		r.GeneratedAt.Format("2006-01-02 15:04:05 MST"), r.Summary.Total())), "", 1, "L", false, 0, "")
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(2)
}

func drawSummary(pdf *fpdf.Fpdf, tr func(string) string, s model.SeverityCounts) {
	cells := []struct {
		label string
		n     int
		sev   model.Severity
	}{
		{"Critical", s.Critical, model.SeverityCritical},
		{"High", s.High, model.SeverityHigh},
		{"Medium", s.Medium, model.SeverityMedium},
		{"Low", s.Low, model.SeverityLow},
		{"Info", s.Info, model.SeverityInfo},
	}
	width := 44.0
	for _, c := range cells {
		r, g, bl := severityColor(c.sev)
		pdf.SetFillColor(r, g, bl)
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("Helvetica", "B", 13)
		pdf.CellFormat(width, 11, fmt.Sprintf("%d", c.n), "", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(80, 80, 80)
	for _, c := range cells {
		pdf.CellFormat(width, 5, tr(c.label), "", 0, "C", false, 0, "")
	}
	pdf.Ln(-1)
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(2)

	pdf.SetFont("Helvetica", "I", 9)
	pdf.SetTextColor(154, 52, 18)
	pdf.MultiCell(0, 5, tr(RiskStatement(s)), "", "L", false)
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(3)
}

func drawGroup(pdf *fpdf.Fpdf, tr func(string) string, g ModuleGroup) {
	title := g.Title
	if g.Language != "" {
		title = fmt.Sprintf("%s (%s)", title, g.Language)
	}
	pdf.SetFont("Helvetica", "B", 12)
	pdf.CellFormat(0, 8, tr(title), "", 1, "L", false, 0, "")

	for _, e := range g.Errors {
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetTextColor(154, 52, 18)
		pdf.MultiCell(0, 5, tr("Warning: "+e), "", "L", false)
		pdf.SetTextColor(0, 0, 0)
	}

	if len(g.Rows) == 0 {
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetTextColor(120, 120, 120)
		pdf.CellFormat(0, 6, tr("No findings."), "", 1, "L", false, 0, "")
		pdf.SetTextColor(0, 0, 0)
		pdf.Ln(3)
		return
	}

	drawTableHeader(pdf, tr)
	for i, row := range g.Rows {
		cells := []string{
			fmt.Sprintf("%d", row.SNo),
			fmt.Sprintf("%s (%d)", row.Severity, row.SeverityValue),
			orDash(row.RefID),
			orDash(row.Issue),
			orDash(row.Location),
			orDash(row.Description),
			orDash(row.FixSuggestion),
		}
		fill := i%2 == 1
		drawTableRow(pdf, tr, cells, row.Severity, fill)
	}
	pdf.Ln(4)
}

func drawTableHeader(pdf *fpdf.Fpdf, tr func(string) string) {
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetFillColor(15, 23, 42)
	pdf.SetTextColor(255, 255, 255)
	left, _, _, _ := pdf.GetMargins()
	pdf.SetX(left)
	for i, h := range pdfHeaders {
		pdf.CellFormat(pdfColWidths[i], 7, tr(h), "", 0, "L", true, 0, "")
	}
	pdf.Ln(-1)
	pdf.SetTextColor(0, 0, 0)
}

// drawTableRow renders one wrapped, multi-line table row, breaking to a new
// page (and redrawing the header) if the row wouldn't fit.
func drawTableRow(pdf *fpdf.Fpdf, tr func(string) string, cells []string, sev model.Severity, fill bool) {
	pdf.SetFont("Helvetica", "", 7.5)

	wrapped := make([][]string, len(cells))
	maxLines := 1
	for i, c := range cells {
		lines := pdf.SplitLines([]byte(tr(c)), pdfColWidths[i]-2*pdfCellPad)
		ls := make([]string, 0, len(lines))
		for _, l := range lines {
			ls = append(ls, string(l))
		}
		if len(ls) == 0 {
			ls = []string{""}
		}
		wrapped[i] = ls
		if len(ls) > maxLines {
			maxLines = len(ls)
		}
	}
	rowH := float64(maxLines)*pdfLineHeight + 2*pdfCellPad

	_, pageH := pdf.GetPageSize()
	_, _, _, bottomMargin := pdf.GetMargins()
	if pdf.GetY()+rowH > pageH-bottomMargin {
		pdf.AddPage()
		drawTableHeader(pdf, tr)
	}

	left, _, _, _ := pdf.GetMargins()
	startX := left
	startY := pdf.GetY()

	sr, sg, sb := severityColor(sev)
	rowFillR, rowFillG, rowFillB := 255, 255, 255
	if fill {
		rowFillR, rowFillG, rowFillB = 248, 249, 250
	}

	x := startX
	for i, lines := range wrapped {
		if i == 1 {
			// Severity column gets its own solid color fill so it reads at
			// a glance; every other column uses the row's zebra-stripe fill.
			pdf.SetFillColor(sr, sg, sb)
			pdf.SetTextColor(255, 255, 255)
			pdf.Rect(x, startY, pdfColWidths[i], rowH, "F")
		} else {
			pdf.SetFillColor(rowFillR, rowFillG, rowFillB)
			pdf.SetTextColor(30, 30, 30)
			pdf.Rect(x, startY, pdfColWidths[i], rowH, "F")
		}
		pdf.SetDrawColor(226, 228, 233)
		pdf.Rect(x, startY, pdfColWidths[i], rowH, "D")

		pdf.SetXY(x+pdfCellPad, startY+pdfCellPad)
		for _, line := range lines {
			pdf.CellFormat(pdfColWidths[i]-2*pdfCellPad, pdfLineHeight, line, "", 2, "L", false, 0, "")
			pdf.SetX(x + pdfCellPad)
		}
		x += pdfColWidths[i]
	}

	pdf.SetTextColor(0, 0, 0)
	pdf.SetXY(startX, startY+rowH)
}
