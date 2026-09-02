package container

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"secscantool/internal/model"
)

type trivyOutput struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string               `json:"Target"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	References       []string `json:"References"`
}

// Scan runs `trivy image` against tag and returns normalized findings.
func Scan(ctx context.Context, trivyBin, tag string, onStep func(string)) ([]model.Finding, error) {
	if onStep != nil {
		onStep(fmt.Sprintf("trivy image %s", tag))
	}

	cmd := exec.CommandContext(ctx, trivyBin, "image", "--format", "json", "--quiet", tag)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// trivy exits non-zero depending on --exit-code flags/severity; we don't
	// set those, but treat a run error as fatal only if we got no JSON back.
	runErr := cmd.Run()

	if stdout.Len() == 0 {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" && runErr != nil {
			msg = runErr.Error()
		}
		if msg == "" {
			msg = "trivy produced no output"
		}
		return nil, fmt.Errorf("trivy: %s", msg)
	}

	var out trivyOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("trivy: failed to parse output: %w", err)
	}

	var findings []model.Finding
	for _, result := range out.Results {
		for _, v := range result.Vulnerabilities {
			fix := "no fixed version published yet upstream"
			if v.FixedVersion != "" {
				fix = fmt.Sprintf("rebuild the image after upgrading %s to %s (update your base image or package pin)", v.PkgName, v.FixedVersion)
			}
			title := v.Title
			if title == "" {
				title = v.VulnerabilityID
			}
			var url string
			if len(v.References) > 0 {
				url = v.References[0]
			}
			findings = append(findings, model.Finding{
				Tool:             "trivy",
				Stage:            model.StageContainer,
				RefID:            v.VulnerabilityID,
				URL:              url,
				Severity:         mapTrivySeverity(v.Severity),
				Title:            title,
				Description:      v.Description,
				PackageName:      v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				FixSuggestion:    fix,
			})
		}
	}
	return findings, nil
}

func mapTrivySeverity(s string) model.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return model.SeverityCritical
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
