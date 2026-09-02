// Package nodejs adapts semgrep (code-level SAST) and npm audit
// (dependency vulnerability scanning) to secscantool's scanner interfaces.
package nodejs

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

// SAST runs semgrep's default ruleset over a Node.js/JS/TS module.
type SAST struct{}

func (SAST) Name() string         { return "semgrep" }
func (SAST) Tool() installer.Tool { return installer.ToolSemgrep }

type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Metadata struct {
			CWE        json.RawMessage `json:"cwe"`
			References []string        `json:"references"`
		} `json:"metadata"`
	} `json:"extra"`
}

func (SAST) Scan(ctx context.Context, binPath, modulePath string, report scanner.StepReporter) ([]model.Finding, error) {
	if report != nil {
		report("running semgrep --config=auto")
	}

	cmd := exec.CommandContext(ctx, binPath, "--config=auto", "--json", "--quiet", ".")
	cmd.Dir = modulePath
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// semgrep exits non-zero when findings exist (with --error) or on rule
	// warnings — expected, so we only treat it as fatal if JSON parsing fails.
	_ = cmd.Run()

	if stdout.Len() == 0 {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = "semgrep produced no output"
		}
		return nil, fmt.Errorf("semgrep: %s", msg)
	}

	var out semgrepOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("semgrep: failed to parse output: %w", err)
	}

	findings := make([]model.Finding, 0, len(out.Results))
	for _, r := range out.Results {
		var url string
		if len(r.Extra.Metadata.References) > 0 {
			url = r.Extra.Metadata.References[0]
		}
		findings = append(findings, model.Finding{
			Tool:        "semgrep",
			Stage:       model.StageCode,
			Language:    "nodejs",
			RefID:       r.CheckID,
			URL:         url,
			Severity:    mapSemgrepSeverity(r.Extra.Severity),
			Title:       firstSentence(r.Extra.Message),
			Description: r.Extra.Message,
			File:        r.Path,
			Line:        r.Start.Line,
			CWE:         firstCWE(r.Extra.Metadata.CWE),
		})
	}
	return findings, nil
}

func mapSemgrepSeverity(s string) model.Severity {
	switch strings.ToUpper(s) {
	case "ERROR":
		return model.SeverityHigh
	case "WARNING":
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}

// firstSentence shortens a semgrep rule message down to something that
// reads well as a report table's "Issue" column, falling back to a hard
// character cutoff for messages with no sentence break.
func firstSentence(s string) string {
	s = strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	if i := strings.Index(s, ". "); i > 0 && i < 120 {
		return s[:i+1]
	}
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}

// firstCWE handles semgrep's metadata.cwe field, which is sometimes a single
// string and sometimes an array of strings depending on the rule.
func firstCWE(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return asString
	}
	var asSlice []string
	if err := json.Unmarshal(raw, &asSlice); err == nil && len(asSlice) > 0 {
		return asSlice[0]
	}
	return ""
}
