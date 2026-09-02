package engine

import (
	"context"
	"fmt"
	"time"

	"secscantool/internal/container"
	"secscantool/internal/installer"
	"secscantool/internal/model"
	"secscantool/internal/ui"
)

// ImageOptions configures a standalone container image scan.
type ImageOptions struct {
	// Image is an image reference secscantool will scan as-is: a local
	// image name/tag/id, or a registry reference to pull. secscantool never
	// builds an image itself.
	Image string
}

// RunImage scans an existing Docker image with Trivy, pulling it first if
// it isn't already present locally.
func RunImage(ctx context.Context, opts ImageOptions) (*model.Report, error) {
	report := &model.Report{
		ProjectPath: opts.Image,
		GeneratedAt: time.Now(),
	}

	if !installer.CheckPrerequisite(installer.PrereqDocker) {
		return nil, fmt.Errorf("docker is required to scan an image: %s", installer.PrereqInstallHint(installer.PrereqDocker))
	}

	if err := ui.Step("checking docker daemon", func(update func(string)) error {
		return container.DaemonAvailable(ctx)
	}); err != nil {
		return nil, err
	}

	if !container.ImageExistsLocally(ctx, opts.Image) {
		if err := ui.Step(fmt.Sprintf("image %s not found locally, pulling", opts.Image), func(update func(string)) error {
			return container.Pull(ctx, opts.Image, update)
		}); err != nil {
			return nil, err
		}
	}

	var trivyBin string
	if err := ui.Step("preparing trivy", func(update func(string)) error {
		status := installer.Ensure(ctx, installer.ToolTrivy, update)
		if status.Err != nil {
			return status.Err
		}
		trivyBin = status.Path
		return nil
	}); err != nil {
		return nil, err
	}

	result := model.ModuleResult{Module: opts.Image, Language: "docker"}
	label := fmt.Sprintf("scanning image %s with trivy", opts.Image)
	if err := ui.Step(label, func(update func(string)) error {
		findings, err := container.Scan(ctx, trivyBin, opts.Image, update)
		if err != nil {
			return err
		}
		result.Findings = findings
		update(fmt.Sprintf("%s — %d findings", label, len(findings)))
		return nil
	}); err != nil {
		result.Errors = append(result.Errors, err.Error())
	}

	report.Container = &result
	report.ComputeSummary()
	return report, nil
}
