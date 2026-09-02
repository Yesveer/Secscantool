package main

import (
	"fmt"
	"os"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

// version is overridden at build time via:
//
//	go build -ldflags "-X main.version=1.1.1"
//
// `make release VERSION=1.1.1` sets this for every packaged artifact.
var version = "dev"

var rootCmd = &cobra.Command{
	Use:   "secscantool",
	Short: "Detects your project's language and runs code, dependency, and container vulnerability scans",
	Long: `secscantool

A single CLI that:
  1. Detects which language a project is written in (currently Go and Node.js)
  2. Runs a code-level SAST scan (gosec / semgrep) -- "scan --only code"
  3. Runs a dependency vulnerability scan (govulncheck / npm audit) -- "scan --only dependency"
  4. Scans an existing Docker image with Trivy -- "scan image <name>" (pulls it if needed; never builds one for you)
  5. Writes one unified report (JSON, Markdown, HTML, and PDF)

secscantool ships with none of those scanners bundled — the first time a
language (or an image scan) is run, it installs whichever scanner binaries
that needs, automatically. You only need the language's own runtime
installed (the Go toolchain, or Node.js/npm) and Docker for image scans.`,
	SilenceUsage: true,
}

// Execute runs the root command and exits(1) on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr)
		pterm.Error.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(doctorCmd)
	rootCmd.AddCommand(versionCmd)
}
