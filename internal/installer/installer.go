// Package installer resolves and, when missing, auto-installs the
// third-party scanner binaries secscantool depends on (gosec, govulncheck,
// semgrep, trivy). secscantool itself ships with none of these bundled —
// they are fetched on demand, the first time a scan actually needs them.
//
// Runtime prerequisites (the Go toolchain, Node+npm, Docker) are never
// auto-installed: those are heavy, platform-specific installs the user
// must already have. This package only checks for them and reports a
// clear install hint when absent.
package installer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Tool identifies one auto-installable scanner binary.
type Tool string

const (
	ToolGosec       Tool = "gosec"
	ToolGovulncheck Tool = "govulncheck"
	ToolSemgrep     Tool = "semgrep"
	ToolTrivy       Tool = "trivy"
)

// Prerequisite identifies a runtime the user must install themselves.
type Prerequisite string

const (
	PrereqGo     Prerequisite = "go"
	PrereqNode   Prerequisite = "node"
	PrereqPython Prerequisite = "python"
	PrereqDocker Prerequisite = "docker"
)

// installSpec describes how to auto-install one Tool.
type installSpec struct {
	binaryName string
	prereq     Prerequisite
	install    func(ctx context.Context) error
	resolve    func(ctx context.Context) (string, error)
}

var specs = map[Tool]installSpec{
	ToolGosec: {
		binaryName: "gosec",
		prereq:     PrereqGo,
		install: func(ctx context.Context) error {
			return runVisible(ctx, "go", "install", "github.com/securego/gosec/v2/cmd/gosec@latest")
		},
		resolve: resolveGoBin("gosec"),
	},
	ToolGovulncheck: {
		binaryName: "govulncheck",
		prereq:     PrereqGo,
		install: func(ctx context.Context) error {
			return runVisible(ctx, "go", "install", "golang.org/x/vuln/cmd/govulncheck@latest")
		},
		resolve: resolveGoBin("govulncheck"),
	},
	ToolTrivy: {
		binaryName: "trivy",
		// Trivy has no runtime prerequisite of its own: we fetch a prebuilt,
		// checksum-verified release binary rather than compiling it (trivy's
		// own docs call `go install` unsupported, and it can fail to even
		// compile against a given Go toolchain — confirmed while building
		// secscantool). All that's needed is network access.
		prereq: "",
		install: func(ctx context.Context) error {
			return installTrivyFromRelease(ctx)
		},
		resolve: func(ctx context.Context) (string, error) {
			if p, err := exec.LookPath("trivy"); err == nil {
				return p, nil
			}
			p, err := trivyManagedPath()
			if err != nil {
				return "", err
			}
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
			return "", fmt.Errorf("trivy not found on PATH or in managed install dir")
		},
	},
	ToolSemgrep: {
		binaryName: "semgrep",
		prereq:     PrereqPython,
		// The "semgrep" npm package is an abandoned placeholder stub, not the
		// real tool — semgrep is only officially distributed via PyPI (or OS
		// package managers). Modern Homebrew/Debian Pythons refuse a bare
		// `pip install` (PEP 668), so we manage a small dedicated virtualenv
		// under the user's cache dir instead of touching the system Python.
		install: func(ctx context.Context) error {
			venvDir, err := semgrepVenvDir()
			if err != nil {
				return err
			}
			if _, err := os.Stat(venvBinPath(venvDir, "pip")); err != nil {
				pythonBin := "python3"
				if !lookPath(pythonBin) {
					pythonBin = "python"
				}
				if err := runVisible(ctx, pythonBin, "-m", "venv", venvDir); err != nil {
					return err
				}
			}
			return runVisible(ctx, venvBinPath(venvDir, "pip"), "install", "--upgrade", "semgrep")
		},
		resolve: func(ctx context.Context) (string, error) {
			if p, err := exec.LookPath("semgrep"); err == nil {
				return p, nil
			}
			venvDir, err := semgrepVenvDir()
			if err != nil {
				return "", err
			}
			p := venvBinPath(venvDir, "semgrep")
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
			return "", fmt.Errorf("semgrep not found on PATH or in managed venv %s", venvDir)
		},
	},
}

// semgrepVenvDir is where secscantool keeps its own isolated Python
// virtualenv for semgrep, so installing it never touches system Python
// packages.
func semgrepVenvDir() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("could not determine user cache dir: %w", err)
	}
	return filepath.Join(cacheDir, "secscantool", "semgrep-venv"), nil
}

// venvBinPath returns the path to an executable inside a virtualenv,
// accounting for Windows' different venv layout (Scripts\ + .exe).
func venvBinPath(venvDir, name string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(venvDir, "Scripts", name+".exe")
	}
	return filepath.Join(venvDir, "bin", name)
}

// PrereqInstallHint returns a human-readable install instruction for a
// missing runtime prerequisite.
func PrereqInstallHint(p Prerequisite) string {
	switch p {
	case PrereqGo:
		return "install the Go toolchain from https://go.dev/dl/ (needed to scan Go projects and to fetch gosec/govulncheck/trivy)"
	case PrereqNode:
		return "install Node.js (which includes npm) from https://nodejs.org/ (needed to scan Node.js projects; npm audit ships with it)"
	case PrereqPython:
		return "install Python 3 from https://www.python.org/downloads/ (needed only to fetch semgrep, into a dedicated virtualenv secscantool manages itself)"
	case PrereqDocker:
		return "install Docker from https://docs.docker.com/get-docker/ and make sure the daemon is running (needed for the container scan stage)"
	default:
		return "install the required prerequisite"
	}
}

// CheckPrerequisite reports whether the runtime prerequisite p is available.
// An empty Prerequisite means "none" (e.g. trivy, which only needs network
// access) and is always satisfied.
func CheckPrerequisite(p Prerequisite) bool {
	switch p {
	case "":
		return true
	case PrereqGo:
		return lookPath("go")
	case PrereqNode:
		return lookPath("node") && lookPath("npm")
	case PrereqPython:
		return lookPath("python3") || lookPath("python")
	case PrereqDocker:
		return lookPath("docker")
	default:
		return false
	}
}

// Status describes whether a Tool is available, and whether it had to be installed.
type Status struct {
	Tool      Tool
	Path      string
	AlreadyOK bool // was already on the system before we looked
	Installed bool // we installed it just now
	Err       error
}

// AllTools lists every auto-installable tool, in a stable order — used by
// `secscantool doctor` to report status without installing anything.
func AllTools() []Tool {
	return []Tool{ToolGosec, ToolGovulncheck, ToolSemgrep, ToolTrivy}
}

// Probe reports whether tool is currently installed, without installing it.
func Probe(ctx context.Context, tool Tool) (path string, prereqOK bool, found bool) {
	spec, ok := specs[tool]
	if !ok {
		return "", false, false
	}
	prereqOK = CheckPrerequisite(spec.prereq)
	if !prereqOK {
		return "", false, false
	}
	path, err := spec.resolve(ctx)
	return path, true, err == nil && path != ""
}

// PrereqOf returns which runtime prerequisite a tool depends on.
func PrereqOf(tool Tool) Prerequisite {
	return specs[tool].prereq
}

// Ensure makes sure tool is available, installing it on demand if missing.
// It returns the resolved absolute path to the binary to invoke.
func Ensure(ctx context.Context, tool Tool, onStep func(msg string)) Status {
	spec, ok := specs[tool]
	if !ok {
		return Status{Tool: tool, Err: fmt.Errorf("unknown tool %q", tool)}
	}

	if !CheckPrerequisite(spec.prereq) {
		return Status{Tool: tool, Err: fmt.Errorf("prerequisite %q missing: %s", spec.prereq, PrereqInstallHint(spec.prereq))}
	}

	if path, err := spec.resolve(ctx); err == nil && path != "" {
		return Status{Tool: tool, Path: path, AlreadyOK: true}
	}

	if onStep != nil {
		onStep(fmt.Sprintf("%s not found — installing...", spec.binaryName))
	}
	if err := spec.install(ctx); err != nil {
		return Status{Tool: tool, Err: fmt.Errorf("failed to install %s: %w", spec.binaryName, err)}
	}

	path, err := spec.resolve(ctx)
	if err != nil || path == "" {
		return Status{Tool: tool, Err: fmt.Errorf("%s installed but could not be located afterward: %v", spec.binaryName, err)}
	}
	return Status{Tool: tool, Path: path, Installed: true}
}

func lookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// runVisible runs a command with combined output surfaced only on failure
// (its stdout/stderr is noisy install-log spam we don't want cluttering a
// successful run, but we need it for diagnosing a failure).
func runVisible(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, string(out))
	}
	return nil
}

// resolveGoBin looks for name on PATH first, then falls back to the Go
// toolchain's own install directory (`go env GOBIN` / `go env GOPATH`/bin),
// since `go install` binaries often land somewhere not yet on the user's PATH.
func resolveGoBin(name string) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
		goBin, err := goEnv(ctx, "GOBIN")
		if err == nil && goBin != "" {
			if p := joinIfExists(goBin, name); p != "" {
				return p, nil
			}
		}
		goPath, err := goEnv(ctx, "GOPATH")
		if err == nil && goPath != "" {
			if p := joinIfExists(filepath.Join(goPath, "bin"), name); p != "" {
				return p, nil
			}
		}
		return "", fmt.Errorf("%s not found on PATH or in go bin dirs", name)
	}
}

func goEnv(ctx context.Context, key string) (string, error) {
	cmd := exec.CommandContext(ctx, "go", "env", key)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func joinIfExists(dir, name string) string {
	if dir == "" {
		return ""
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(name, ".exe") {
		name += ".exe"
	}
	candidate := filepath.Join(dir, name)
	// LookPath on an absolute path just checks the file exists and is executable.
	if _, err := exec.LookPath(candidate); err == nil {
		return candidate
	}
	return ""
}
