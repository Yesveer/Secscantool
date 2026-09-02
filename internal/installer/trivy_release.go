package installer

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Trivy is only officially distributed as prebuilt release archives (its
// own docs call `go install` unsupported, and in practice it can fail to
// even compile against a given Go toolchain — confirmed while building
// secscantool). So instead of `go install`, we download the matching
// release archive from GitHub, verify it against trivy's own published
// sha256 checksums file, and extract just the binary into a secscantool-
// managed cache dir. No shell scripts are ever executed.

const trivyRepo = "aquasecurity/trivy"

func trivyBinDir() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("could not determine user cache dir: %w", err)
	}
	return filepath.Join(cacheDir, "secscantool", "bin"), nil
}

func trivyManagedPath() (string, error) {
	dir, err := trivyBinDir()
	if err != nil {
		return "", err
	}
	name := "trivy"
	if runtime.GOOS == "windows" {
		name = "trivy.exe"
	}
	return filepath.Join(dir, name), nil
}

// installTrivyFromRelease downloads, verifies, and installs the trivy
// binary for the current OS/arch into trivyManagedPath().
func installTrivyFromRelease(ctx context.Context) error {
	tag, err := latestGitHubReleaseTag(ctx, trivyRepo)
	if err != nil {
		return fmt.Errorf("could not determine latest trivy release: %w", err)
	}
	version := strings.TrimPrefix(tag, "v")

	assetName, err := trivyAssetName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	assetFile := fmt.Sprintf("trivy_%s_%s", version, assetName)
	checksumsFile := fmt.Sprintf("trivy_%s_checksums.txt", version)
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s", trivyRepo, tag)

	checksums, err := httpGetBytes(ctx, base+"/"+checksumsFile)
	if err != nil {
		return fmt.Errorf("downloading checksums: %w", err)
	}
	wantSum, err := findChecksum(string(checksums), assetFile)
	if err != nil {
		return err
	}

	archive, err := httpGetBytes(ctx, base+"/"+assetFile)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", assetFile, err)
	}

	gotSum := sha256.Sum256(archive)
	if hex.EncodeToString(gotSum[:]) != wantSum {
		return fmt.Errorf("checksum mismatch for %s — refusing to install a corrupted/tampered download", assetFile)
	}

	binName := "trivy"
	if runtime.GOOS == "windows" {
		binName = "trivy.exe"
	}
	var binData []byte
	if strings.HasSuffix(assetFile, ".zip") {
		binData, err = extractFromZip(archive, binName)
	} else {
		binData, err = extractFromTarGz(archive, binName)
	}
	if err != nil {
		return fmt.Errorf("extracting %s from %s: %w", binName, assetFile, err)
	}

	destDir, err := trivyBinDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	destPath := filepath.Join(destDir, binName)
	if err := os.WriteFile(destPath, binData, 0o755); err != nil {
		return err
	}
	return nil
}

// trivyAssetName maps a Go GOOS/GOARCH pair to trivy's release asset
// suffix. Trivy does not publish a windows/arm64 asset.
func trivyAssetName(goos, goarch string) (string, error) {
	switch goos {
	case "darwin":
		switch goarch {
		case "arm64":
			return "macOS-ARM64.tar.gz", nil
		case "amd64":
			return "macOS-64bit.tar.gz", nil
		}
	case "linux":
		switch goarch {
		case "amd64":
			return "Linux-64bit.tar.gz", nil
		case "arm64":
			return "Linux-ARM64.tar.gz", nil
		case "arm":
			return "Linux-ARM.tar.gz", nil
		case "386":
			return "Linux-32bit.tar.gz", nil
		case "ppc64le":
			return "Linux-PPC64LE.tar.gz", nil
		case "s390x":
			return "Linux-s390x.tar.gz", nil
		}
	case "windows":
		if goarch == "amd64" {
			return "windows-64bit.zip", nil
		}
	}
	return "", fmt.Errorf("no trivy release binary available for %s/%s", goos, goarch)
}

func findChecksum(checksumsText, filename string) (string, error) {
	for _, line := range strings.Split(checksumsText, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == filename {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no checksum entry found for %s", filename)
}

func extractFromTarGz(data []byte, wantName string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == wantName {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("%s not found in archive", wantName)
}

func extractFromZip(data []byte, wantName string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) == wantName {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("%s not found in archive", wantName)
}

// latestGitHubReleaseTag resolves owner/repo's "latest" release tag by
// following GitHub's redirect (releases/latest -> releases/tag/vX.Y.Z)
// without hitting the rate-limited REST API.
func latestGitHubReleaseTag(ctx context.Context, repo string) (string, error) {
	url := fmt.Sprintf("https://github.com/%s/releases/latest", repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("unexpected response resolving latest release (status %d, no redirect)", resp.StatusCode)
	}
	return filepath.Base(loc), nil
}

func httpGetBytes(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}
