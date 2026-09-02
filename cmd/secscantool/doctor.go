package main

import (
	"context"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	"secscantool/internal/installer"
	"secscantool/internal/ui"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check which runtime prerequisites and scanner tools are installed",
	Long: `Check which runtime prerequisites (Go, Node.js/npm, Docker) and
scanner tools (gosec, govulncheck, semgrep, trivy) are currently available,
without installing or scanning anything. Useful before running "scan" on a
new machine, or to see what secscantool will auto-install on first use.`,
	RunE: runDoctor,
}

func runDoctor(cmd *cobra.Command, args []string) error {
	ui.Banner()
	ctx := context.Background()

	pterm.DefaultSection.Println("Runtime Prerequisites")
	prereqTable := pterm.TableData{{"Prerequisite", "Status", "Needed for"}}
	prereqs := []struct {
		p         installer.Prerequisite
		neededFor string
	}{
		{installer.PrereqGo, "Go projects, gosec, govulncheck"},
		{installer.PrereqNode, "Node.js projects, npm audit"},
		{installer.PrereqPython, "semgrep (installed into its own managed virtualenv)"},
		{installer.PrereqDocker, "pulling + scanning container images (scan image)"},
	}
	for _, pr := range prereqs {
		status := pterm.FgRed.Sprint("✗ missing")
		if installer.CheckPrerequisite(pr.p) {
			status = pterm.FgGreen.Sprint("✓ found")
		}
		prereqTable = append(prereqTable, []string{string(pr.p), status, pr.neededFor})
	}
	_ = pterm.DefaultTable.WithHasHeader().WithData(prereqTable).Render()

	pterm.Println()
	pterm.DefaultSection.Println("Scanner Tools (auto-installed on first use)")
	toolTable := pterm.TableData{{"Tool", "Status", "Path"}}
	for _, t := range installer.AllTools() {
		path, prereqOK, found := installer.Probe(ctx, t)
		status := pterm.FgYellow.Sprint("○ not installed (will auto-install)")
		if !prereqOK {
			status = pterm.FgRed.Sprintf("✗ blocked — %s missing", installer.PrereqOf(t))
		} else if found {
			status = pterm.FgGreen.Sprint("✓ installed")
		}
		toolTable = append(toolTable, []string{string(t), status, path})
	}
	_ = pterm.DefaultTable.WithHasHeader().WithData(toolTable).Render()

	pterm.Println()
	pterm.Info.Println("npm audit needs no separate install — it ships with npm itself.")
	return nil
}
