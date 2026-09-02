package report

import (
	"fmt"

	"github.com/pterm/pterm"

	"secscantool/internal/model"
)

// PrintSummary renders a colored summary table + top findings to the
// terminal, independent of whatever file formats were also written.
func PrintSummary(r *model.Report) {
	pterm.DefaultSection.Println("Scan Summary")

	tableData := pterm.TableData{
		{"Module", "Language", "Critical", "High", "Medium", "Low", "Info"},
	}
	for _, m := range r.Modules {
		var c model.SeverityCounts
		for _, f := range m.Findings {
			c.Add(f.Severity)
		}
		name := m.Module
		if name == "" || name == "." {
			name = "(root)"
		}
		tableData = append(tableData, []string{
			name, m.Language,
			sevCell(c.Critical, pterm.FgRed),
			sevCell(c.High, pterm.FgRed),
			sevCell(c.Medium, pterm.FgYellow),
			sevCell(c.Low, pterm.FgBlue),
			sevCell(c.Info, pterm.FgGray),
		})
	}
	if r.Container != nil {
		var c model.SeverityCounts
		for _, f := range r.Container.Findings {
			c.Add(f.Severity)
		}
		tableData = append(tableData, []string{
			"(container image)", "docker",
			sevCell(c.Critical, pterm.FgRed),
			sevCell(c.High, pterm.FgRed),
			sevCell(c.Medium, pterm.FgYellow),
			sevCell(c.Low, pterm.FgBlue),
			sevCell(c.Info, pterm.FgGray),
		})
	}

	_ = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()

	pterm.Println()
	total := r.Summary.Total()
	if total == 0 {
		pterm.Success.Println("No findings — clean scan!")
		return
	}

	line := fmt.Sprintf("%d total findings — %d critical, %d high, %d medium, %d low, %d info",
		total, r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info)
	switch {
	case r.Summary.Critical > 0 || r.Summary.High > 0:
		pterm.Error.Println(line)
	case r.Summary.Medium > 0:
		pterm.Warning.Println(line)
	default:
		pterm.Info.Println(line)
	}
}

func sevCell(n int, color pterm.Color) string {
	if n == 0 {
		return pterm.Gray("0")
	}
	return color.Sprintf("%d", n)
}
