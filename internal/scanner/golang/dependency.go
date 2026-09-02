package golang

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"secscantool/internal/installer"
	"secscantool/internal/model"
	"secscantool/internal/scanner"
)

// Dependency runs govulncheck over a Go module.
type Dependency struct{}

func (Dependency) Name() string         { return "govulncheck" }
func (Dependency) Tool() installer.Tool { return installer.ToolGovulncheck }
func (Dependency) FixCommand(modulePath string) string {
	return "go get -u ./... && go mod tidy   # then re-run govulncheck to confirm"
}

// govulncheck -json emits a stream of concatenated JSON objects (not one
// array), each with exactly one of these fields populated.
type govulnMessage struct {
	OSV     *osvEntry     `json:"osv,omitempty"`
	Finding *findingEntry `json:"finding,omitempty"`
}

type osvEntry struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	Details string `json:"details"`
}

type findingEntry struct {
	OSV          string       `json:"osv"`
	FixedVersion string       `json:"fixed_version"`
	Trace        []traceFrame `json:"trace"`
}

type traceFrame struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Position *struct {
		Filename string `json:"filename"`
		Line     int    `json:"line"`
	} `json:"position,omitempty"`
}

func (Dependency) Scan(ctx context.Context, binPath, modulePath string, report scanner.StepReporter) ([]model.Finding, error) {
	if report != nil {
		report("running govulncheck ./...")
	}

	cmd := exec.CommandContext(ctx, binPath, "-json", "./...")
	cmd.Dir = modulePath
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// govulncheck exits non-zero when vulnerabilities are found — expected.
	_ = cmd.Run()

	osvByID := map[string]osvEntry{}
	var findingEntries []findingEntry

	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decodedAny := false
	for {
		var msg govulnMessage
		if err := dec.Decode(&msg); err != nil {
			break
		}
		decodedAny = true
		if msg.OSV != nil {
			osvByID[msg.OSV.ID] = *msg.OSV
		}
		if msg.Finding != nil {
			findingEntries = append(findingEntries, *msg.Finding)
		}
	}

	if !decodedAny {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = "govulncheck produced no parseable output"
		}
		return nil, fmt.Errorf("govulncheck: %s", msg)
	}

	findings := make([]model.Finding, 0, len(findingEntries))
	for _, f := range findingEntries {
		osv := osvByID[f.OSV]
		title := osv.Summary
		if title == "" {
			title = f.OSV
		}

		var pkg, file string
		var line int
		if len(f.Trace) > 0 {
			pkg = f.Trace[0].Module
			if f.Trace[0].Position != nil {
				file = f.Trace[0].Position.Filename
				line = f.Trace[0].Position.Line
			}
		}

		fix := fmt.Sprintf("go get %s@%s && go mod tidy", pkg, f.FixedVersion)
		if f.FixedVersion == "" {
			fix = "no fixed version published yet upstream — monitor " + f.OSV
		}

		findings = append(findings, model.Finding{
			Tool:          "govulncheck",
			Stage:         model.StageDependency,
			Language:      "go",
			RefID:         f.OSV,
			URL:           "https://pkg.go.dev/vuln/" + f.OSV,
			Severity:      model.SeverityHigh,
			Title:         title,
			Description:   osv.Details,
			File:          file,
			Line:          line,
			PackageName:   pkg,
			FixedVersion:  f.FixedVersion,
			FixSuggestion: fix,
		})
	}
	return findings, nil
}
