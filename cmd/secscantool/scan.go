package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	"secscantool/internal/engine"
	"secscantool/internal/model"
	"secscantool/internal/report"
	"secscantool/internal/ui"
)

var (
	outputFlag string
	onlyFlag   []string
)

var scanCmd = &cobra.Command{
	Use:   "scan <repo-path>",
	Short: "Scan a project's code and dependencies (see also: scan image)",
	Long: `Scan a local project's code and dependencies for vulnerabilities.

secscantool detects the project's language from <repo-path> (looking for
go.mod / package.json, monorepo-aware), installs whatever scanner tools
that language needs (if not already installed), and runs a code-level SAST
scan and a dependency vulnerability scan for every detected module.

secscantool never builds a Docker image from your repo. To scan a
container image, build or pull it yourself and run "secscantool scan image
<name>" separately.

By default both the code scan and the dependency scan run. Use --only to
run just one of them.

A unified report (report.json, report.md, report.html, report.pdf) is
written to the output directory: --output if given, otherwise
./secscantool-report in the directory you run this command from.`,
	Example: `  secscantool scan .
  secscantool scan ../my-api --output ./scan-results
  secscantool scan ../my-api --only code
  secscantool scan ../my-api --only dependency`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&outputFlag, "output", "o", "", "directory to write the report into (default: ./secscantool-report in the current directory)")
	scanCmd.Flags().StringSliceVar(&onlyFlag, "only", nil, "restrict scanning to specific stages: code, dependency (comma-separated; default: both)")
}

// parseStages turns --only into an engine.Stages, defaulting to running
// every stage when --only wasn't given.
func parseStages(only []string) (engine.Stages, error) {
	if len(only) == 0 {
		return engine.Stages{Code: true, Dependency: true}, nil
	}
	var stages engine.Stages
	for _, s := range only {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "code":
			stages.Code = true
		case "dependency", "dep", "deps", "library", "libraries":
			stages.Dependency = true
		default:
			return engine.Stages{}, fmt.Errorf("unknown --only value %q (expected: code, dependency)", s)
		}
	}
	return stages, nil
}

// resolveOutputDir returns the absolute output directory for a report,
// creating it if needed. An empty flagVal defaults to ./secscantool-report
// in the current working directory.
func resolveOutputDir(flagVal string) (string, error) {
	outDir := flagVal
	if outDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		outDir = filepath.Join(cwd, "secscantool-report")
	} else {
		abs, err := filepath.Abs(outDir)
		if err != nil {
			return "", err
		}
		outDir = abs
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("could not create output directory %s: %w", outDir, err)
	}
	return outDir, nil
}

// writeReports renders result into every report format in outDir and
// prints their paths plus the colored terminal summary.
func writeReports(result *model.Report, outDir string) error {
	pterm.Println()
	pterm.DefaultSection.Println("Writing Report")

	jsonPath, err := report.WriteJSON(result, outDir)
	if err != nil {
		return err
	}
	mdPath, err := report.WriteMarkdown(result, outDir)
	if err != nil {
		return err
	}
	htmlPath, err := report.WriteHTML(result, outDir)
	if err != nil {
		return err
	}
	pdfPath, err := report.WritePDF(result, outDir)
	if err != nil {
		return err
	}

	pterm.Success.Printfln("JSON report:     %s", jsonPath)
	pterm.Success.Printfln("Markdown report: %s", mdPath)
	pterm.Success.Printfln("HTML report:     %s", htmlPath)
	pterm.Success.Printfln("PDF report:      %s", pdfPath)
	pterm.Println()

	report.PrintSummary(result)
	return nil
}

func runScan(cmd *cobra.Command, args []string) error {
	ui.Banner()

	projectPath, err := filepath.Abs(args[0])
	if err != nil {
		return err
	}
	if info, err := os.Stat(projectPath); err != nil || !info.IsDir() {
		return fmt.Errorf("%s is not a directory", projectPath)
	}

	stages, err := parseStages(onlyFlag)
	if err != nil {
		return err
	}

	outDir, err := resolveOutputDir(outputFlag)
	if err != nil {
		return err
	}

	opts := engine.Options{
		ProjectPath: projectPath,
		Stages:      stages,
	}

	result, err := engine.Run(context.Background(), opts)
	if err != nil {
		return err
	}

	return writeReports(result, outDir)
}
