// Package golang adapts gosec (code-level SAST) and govulncheck
// (dependency vulnerability scanning) to secscantool's scanner interfaces.
package golang

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"secscantool/internal/installer"
	"secscantool/internal/model"
	"secscantool/internal/scanner"
)

// SAST runs gosec over a Go module.
type SAST struct{}

func (SAST) Name() string         { return "gosec" }
func (SAST) Tool() installer.Tool { return installer.ToolGosec }

type gosecOutput struct {
	Issues []gosecIssue `json:"Issues"`
}

type gosecIssue struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	RuleID     string `json:"rule_id"`
	Details    string `json:"details"`
	File       string `json:"file"`
	Line       string `json:"line"`
	CWE        struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	} `json:"cwe"`
}

func (SAST) Scan(ctx context.Context, binPath, modulePath string, report scanner.StepReporter) ([]model.Finding, error) {
	if report != nil {
		report("running gosec ./...")
	}

	cmd := exec.CommandContext(ctx, binPath, "-fmt=json", "-quiet", "./...")
	cmd.Dir = modulePath
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// gosec exits non-zero when it finds issues (or when a package fails to
	// build) — that's expected, so a run error is only fatal if we also
	// failed to get parseable JSON out of it below.
	_ = cmd.Run()

	if stdout.Len() == 0 {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = "gosec produced no output"
		}
		return nil, fmt.Errorf("gosec: %s", msg)
	}

	var out gosecOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("gosec: failed to parse output: %w", err)
	}

	findings := make([]model.Finding, 0, len(out.Issues))
	for _, issue := range out.Issues {
		line, _ := strconv.Atoi(strings.SplitN(issue.Line, "-", 2)[0])
		findings = append(findings, model.Finding{
			Tool:        "gosec",
			Stage:       model.StageCode,
			Language:    "go",
			RefID:       issue.RuleID,
			Severity:    mapGosecSeverity(issue.Severity),
			Title:       issue.Details,
			Description: issue.Details,
			File:        issue.File,
			Line:        line,
			CWE:         issue.CWE.ID,
			URL:         issue.CWE.URL,
		})
	}
	return findings, nil
}

func mapGosecSeverity(s string) model.Severity {
	switch strings.ToUpper(s) {
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}
