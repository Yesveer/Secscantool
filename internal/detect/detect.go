// Package detect walks a project directory and figures out which
// languages/ecosystems are present, so the engine knows which scanner
// adapters to run — without the user ever specifying the language.
package detect

import (
	"os"
	"path/filepath"
)

// Language is one of the ecosystems secscantool knows how to scan.
type Language string

const (
	LanguageGo   Language = "go"
	LanguageNode Language = "nodejs"
)

// skipDirs are never descended into: they're either huge, vendored, or
// version-control internals — walking them wastes time and can produce
// bogus nested "modules".
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	".venv":        true,
	"venv":         true,
	"dist":         true,
	"build":        true,
	".next":        true,
	"target":       true,
}

// signature maps a manifest filename to the language it indicates.
var signatures = map[string]Language{
	"go.mod":       LanguageGo,
	"package.json": LanguageNode,
}

// Module is one detected project module: a directory containing a
// recognized manifest file for a given language.
type Module struct {
	// Path is the absolute path to the module directory.
	Path string
	// RelPath is the path relative to the scan root ("." for the root itself).
	RelPath  string
	Language Language
}

// Scan walks root looking for manifest files and returns one Module per
// match, supporting monorepos with multiple modules/languages.
func Scan(root string) ([]Module, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	var modules []Module
	err = filepath.WalkDir(absRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != absRoot && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		lang, ok := signatures[d.Name()]
		if !ok {
			return nil
		}
		dir := filepath.Dir(path)
		rel, err := filepath.Rel(absRoot, dir)
		if err != nil {
			rel = dir
		}
		modules = append(modules, Module{
			Path:     dir,
			RelPath:  rel,
			Language: lang,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return modules, nil
}

// HasDockerfile reports whether root contains a Dockerfile at its top level.
func HasDockerfile(root string) bool {
	_, err := os.Stat(filepath.Join(root, "Dockerfile"))
	return err == nil
}
