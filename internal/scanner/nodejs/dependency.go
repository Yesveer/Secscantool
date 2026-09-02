package nodejs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"secscantool/internal/installer"
	"secscantool/internal/model"
	"secscantool/internal/scanner"
)

var ghsaPattern = regexp.MustCompile(`GHSA-[a-z0-9-]+`)

// Dependency runs `npm audit` over a Node.js module. npm audit needs no
// separate install — it's built into npm — so its Tool() has no auto-install
// spec; the engine only needs to confirm the Node/npm prerequisite exists.
type Dependency struct{}

func (Dependency) Name() string { return "npm-audit" }

// Tool returns "" because npm audit ships with npm itself; there is nothing
// for the installer package to fetch on demand.
func (Dependency) Tool() installer.Tool { return "" }

func (Dependency) FixCommand(modulePath string) string {
	return "npm audit fix   # add --force if a breaking major-version bump is required"
}

type npmAuditOutput struct {
	Vulnerabilities map[string]npmVuln `json:"vulnerabilities"`
}

type npmVuln struct {
	Name         string            `json:"name"`
	Severity     string            `json:"severity"`
	Range        string            `json:"range"`
	Via          []json.RawMessage `json:"via"`
	FixAvailable json.RawMessage   `json:"fixAvailable"`
}

type npmViaDetail struct {
	Title    string          `json:"title"`
	URL      string          `json:"url"`
	Severity string          `json:"severity"`
	CWE      json.RawMessage `json:"cwe"`
	Range    string          `json:"range"`
}

type npmFixDetail struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	IsSemVerMajor bool   `json:"isSemVerMajor"`
}

// Scan runs `npm audit --json`. It currently targets npm projects
// specifically (package-lock.json); yarn/pnpm audit have different JSON
// schemas and are a natural follow-up adapter, not built in v1.
func (Dependency) Scan(ctx context.Context, binPath, modulePath string, report scanner.StepReporter) ([]model.Finding, error) {
	if report != nil {
		report("running npm audit --json")
	}

	cmd := exec.CommandContext(ctx, "npm", "audit", "--json")
	cmd.Dir = modulePath
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// npm audit exits non-zero when vulnerabilities are found — expected.
	_ = cmd.Run()

	if stdout.Len() == 0 {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = "npm audit produced no output"
		}
		return nil, fmt.Errorf("npm audit: %s", msg)
	}

	var out npmAuditOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("npm audit: failed to parse output: %w", err)
	}

	var findings []model.Finding
	for pkgName, vuln := range out.Vulnerabilities {
		fixSuggestion := fixSuggestionFor(vuln.FixAvailable)

		detailAdded := false
		for _, raw := range vuln.Via {
			var detail npmViaDetail
			if err := json.Unmarshal(raw, &detail); err != nil || detail.Title == "" {
				// A plain string entry just references another vulnerable
				// package already covered by its own map entry — skip it.
				continue
			}
			detailAdded = true
			refID := ghsaPattern.FindString(detail.URL)
			findings = append(findings, model.Finding{
				Tool:             "npm-audit",
				Stage:            model.StageDependency,
				Language:         "nodejs",
				RefID:            refID,
				URL:              detail.URL,
				Severity:         mapNpmSeverity(detail.Severity),
				Title:            detail.Title,
				Description:      fmt.Sprintf("affects %s %s", pkgName, detail.Range),
				PackageName:      pkgName,
				InstalledVersion: vuln.Range,
				FixSuggestion:    fixSuggestion,
				CWE:              firstCWE(detail.CWE),
			})
		}

		if !detailAdded {
			// No structured advisory detail available — still surface the
			// package-level severity so the vulnerability isn't silently dropped.
			findings = append(findings, model.Finding{
				Tool:             "npm-audit",
				Stage:            model.StageDependency,
				Language:         "nodejs",
				Severity:         mapNpmSeverity(vuln.Severity),
				Title:            fmt.Sprintf("vulnerable dependency: %s", pkgName),
				PackageName:      pkgName,
				InstalledVersion: vuln.Range,
				FixSuggestion:    fixSuggestion,
			})
		}
	}
	return findings, nil
}

func fixSuggestionFor(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "npm audit fix"
	}
	var asBool bool
	if err := json.Unmarshal(raw, &asBool); err == nil {
		if asBool {
			return "npm audit fix"
		}
		return "no automatic fix available yet — check the advisory for a manual upgrade path"
	}
	var detail npmFixDetail
	if err := json.Unmarshal(raw, &detail); err == nil && detail.Name != "" {
		if detail.IsSemVerMajor {
			return fmt.Sprintf("npm audit fix --force   # upgrades %s to %s (breaking major version bump)", detail.Name, detail.Version)
		}
		return fmt.Sprintf("npm audit fix   # upgrades %s to %s", detail.Name, detail.Version)
	}
	return "npm audit fix"
}

func mapNpmSeverity(s string) model.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "moderate":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}
