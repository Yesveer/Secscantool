// Package scanner defines the plugin contract every language adapter
// implements. Adding a new language later means writing a new adapter
// package that satisfies these two interfaces and registering it — the
// engine, report generator, and CLI never change.
package scanner

import (
	"context"

	"secscantool/internal/installer"
	"secscantool/internal/model"
)

// StepReporter lets an adapter surface live progress lines to the CLI
// (e.g. "installing gosec...", "running gosec...", "3 findings") without
// depending on any specific UI library.
type StepReporter func(msg string)

// CodeScanner runs a static-analysis (SAST) pass over a module's source.
type CodeScanner interface {
	Name() string
	Tool() installer.Tool
	Scan(ctx context.Context, binPath, modulePath string, report StepReporter) ([]model.Finding, error)
}

// DependencyScanner runs a library/dependency vulnerability pass.
type DependencyScanner interface {
	Name() string
	Tool() installer.Tool
	Scan(ctx context.Context, binPath, modulePath string, report StepReporter) ([]model.Finding, error)
	// FixCommand is the human-facing remediation command suggested in the report.
	FixCommand(modulePath string) string
}
