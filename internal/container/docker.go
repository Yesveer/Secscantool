// Package container scans an existing Docker image with Trivy — the
// "container level" stage of secscantool. It never builds an image itself:
// the user points secscantool at an image they already built (or one in a
// registry), and it's pulled if not already present locally.
package container

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// DaemonAvailable checks docker isn't just installed but actually reachable
// (the daemon can be stopped even when the CLI binary is on PATH).
func DaemonAvailable(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("docker daemon not reachable: %s", msg)
	}
	return nil
}

// ImageExistsLocally reports whether ref is already present in the local
// Docker image store, so scanning it doesn't require a pull first.
func ImageExistsLocally(ctx context.Context, ref string) bool {
	cmd := exec.CommandContext(ctx, "docker", "image", "inspect", ref)
	return cmd.Run() == nil
}

// Pull downloads ref from its registry.
func Pull(ctx context.Context, ref string, onStep func(string)) error {
	if onStep != nil {
		onStep(fmt.Sprintf("docker pull %s", ref))
	}
	cmd := exec.CommandContext(ctx, "docker", "pull", ref)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker pull failed: %w\n%s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
