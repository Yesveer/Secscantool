// Package report renders a model.Report to JSON, Markdown, HTML, and a
// colored terminal summary table.
package report

import (
	"encoding/json"
	"os"
	"path/filepath"

	"secscantool/internal/model"
)

// WriteJSON writes the full machine-readable report to <dir>/report.json.
func WriteJSON(r *model.Report, dir string) (string, error) {
	path := filepath.Join(dir, "report.json")
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}
