// Package engine orchestrates a scan run: detect languages, ensure scanner
// tools are installed, and run code + dependency scanners per module. This
// is the only package that sequences the other internal packages — the CLI
// layer just calls Run and renders the result.
//
// Container image scanning is a separate, explicit flow (see image.go):
// secscantool never builds a Docker image from a project itself.
package engine

import (
	"context"
	"fmt"
	"time"

	"secscantool/internal/detect"
	"secscantool/internal/installer"
	"secscantool/internal/model"
	"secscantool/internal/registry"
	"secscantool/internal/ui"
)

// Stages selects which scan stages to run for a project scan. At least one
// must be true.
type Stages struct {
	Code       bool
	Dependency bool
}

// Options configures a project scan run.
type Options struct {
	ProjectPath string
	Stages      Stages
}

func prereqFor(lang detect.Language) installer.Prerequisite {
	switch lang {
	case detect.LanguageGo:
		return installer.PrereqGo
	case detect.LanguageNode:
		return installer.PrereqNode
	default:
		return ""
	}
}

// Run executes the code/dependency scan pipeline and returns the
// aggregated report.
func Run(ctx context.Context, opts Options) (*model.Report, error) {
	report := &model.Report{
		ProjectPath: opts.ProjectPath,
		GeneratedAt: time.Now(),
	}

	var modules []detect.Module
	err := ui.Step(fmt.Sprintf("detecting language in %s", opts.ProjectPath), func(update func(string)) error {
		var err error
		modules, err = detect.Scan(opts.ProjectPath)
		if err != nil {
			return err
		}
		if len(modules) == 0 {
			return fmt.Errorf("no supported project (go.mod / package.json) found")
		}
		names := make([]string, 0, len(modules))
		for _, m := range modules {
			names = append(names, fmt.Sprintf("%s (%s)", displayModule(m.RelPath), m.Language))
		}
		update(fmt.Sprintf("detecting language — found: %v", names))
		return nil
	})
	if err != nil {
		return nil, err
	}

	for _, mod := range modules {
		result := scanModule(ctx, mod, opts.Stages)
		report.Modules = append(report.Modules, result)
	}

	report.ComputeSummary()
	return report, nil
}

func displayModule(rel string) string {
	if rel == "" || rel == "." {
		return "(root)"
	}
	return rel
}

func scanModule(ctx context.Context, mod detect.Module, stages Stages) model.ModuleResult {
	result := model.ModuleResult{
		Module:   displayModule(mod.RelPath),
		Language: string(mod.Language),
	}

	prereq := prereqFor(mod.Language)
	if prereq != "" && !installer.CheckPrerequisite(prereq) {
		result.Errors = append(result.Errors, fmt.Sprintf(
			"skipped: missing prerequisite %q — %s", prereq, installer.PrereqInstallHint(prereq)))
		return result
	}

	entry, ok := registry.Lookup(mod.Language)
	if !ok {
		result.Errors = append(result.Errors, fmt.Sprintf("no scanner registered for language %q", mod.Language))
		return result
	}

	if stages.Code && entry.Code != nil {
		label := fmt.Sprintf("[%s] code scan (%s)", result.Module, entry.Code.Name())
		_ = ui.Step(label, func(update func(string)) error {
			binPath, err := ensureTool(ctx, entry.Code.Tool(), update)
			if err != nil {
				result.Errors = append(result.Errors, err.Error())
				return err
			}
			findings, err := entry.Code.Scan(ctx, binPath, mod.Path, update)
			if err != nil {
				result.Errors = append(result.Errors, err.Error())
				return err
			}
			result.Findings = append(result.Findings, findings...)
			update(fmt.Sprintf("%s — %d findings", label, len(findings)))
			return nil
		})
	}

	if stages.Dependency && entry.Dependency != nil {
		label := fmt.Sprintf("[%s] dependency scan (%s)", result.Module, entry.Dependency.Name())
		_ = ui.Step(label, func(update func(string)) error {
			binPath, err := ensureTool(ctx, entry.Dependency.Tool(), update)
			if err != nil {
				result.Errors = append(result.Errors, err.Error())
				return err
			}
			findings, err := entry.Dependency.Scan(ctx, binPath, mod.Path, update)
			if err != nil {
				result.Errors = append(result.Errors, err.Error())
				return err
			}
			for i := range findings {
				if findings[i].FixSuggestion == "" {
					findings[i].FixSuggestion = entry.Dependency.FixCommand(mod.Path)
				}
			}
			result.Findings = append(result.Findings, findings...)
			update(fmt.Sprintf("%s — %d findings", label, len(findings)))
			return nil
		})
	}

	return result
}

// ensureTool auto-installs tool if needed. An empty Tool means the scanner
// needs no separate binary (e.g. npm audit ships inside npm itself) — the
// caller passes "" as the binPath, which adapters that don't need it ignore.
func ensureTool(ctx context.Context, tool installer.Tool, update func(string)) (string, error) {
	if tool == "" {
		return "", nil
	}
	status := installer.Ensure(ctx, tool, update)
	if status.Err != nil {
		return "", status.Err
	}
	return status.Path, nil
}
