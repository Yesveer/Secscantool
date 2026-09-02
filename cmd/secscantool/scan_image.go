package main

import (
	"context"

	"github.com/spf13/cobra"

	"secscantool/internal/engine"
	"secscantool/internal/ui"
)

var scanImageCmd = &cobra.Command{
	Use:   "image <image[:tag]>",
	Short: "Scan an existing Docker image for vulnerabilities",
	Long: `Scan a Docker image for vulnerabilities using Trivy.

secscantool does NOT build the image for you. Point it at an image you
already built, or one available in a registry:
  - if the image is already present locally, it's scanned as-is
  - otherwise it's pulled first, then scanned

This is independent of "secscantool scan <path>" (code + dependency
scanning of a project's source) — run both separately if you want full
coverage of a project and its image.`,
	Example: `  secscantool scan image myapp:latest
  secscantool scan image node:18-alpine
  secscantool scan image myregistry.example.com/myapp:1.2.3 --output ./scan-results`,
	Args: cobra.ExactArgs(1),
	RunE: runScanImage,
}

func init() {
	scanImageCmd.Flags().StringVarP(&outputFlag, "output", "o", "", "directory to write the report into (default: ./secscantool-report in the current directory)")
	scanCmd.AddCommand(scanImageCmd)
}

func runScanImage(cmd *cobra.Command, args []string) error {
	ui.Banner()

	outDir, err := resolveOutputDir(outputFlag)
	if err != nil {
		return err
	}

	result, err := engine.RunImage(context.Background(), engine.ImageOptions{Image: args[0]})
	if err != nil {
		return err
	}

	return writeReports(result, outDir)
}
