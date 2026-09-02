// Package registry wires each detect.Language to its scanner adapters.
// This is the one place that needs a one-line addition when a new
// language adapter is written — nothing else in the engine changes.
package registry

import (
	"secscantool/internal/detect"
	"secscantool/internal/scanner"
	"secscantool/internal/scanner/golang"
	"secscantool/internal/scanner/nodejs"
)

// Entry bundles the code + dependency scanners for one language.
type Entry struct {
	Code       scanner.CodeScanner
	Dependency scanner.DependencyScanner
}

var registry = map[detect.Language]Entry{
	detect.LanguageGo: {
		Code:       golang.SAST{},
		Dependency: golang.Dependency{},
	},
	detect.LanguageNode: {
		Code:       nodejs.SAST{},
		Dependency: nodejs.Dependency{},
	},
}

// Lookup returns the scanner Entry for a language, and whether one is registered.
func Lookup(lang detect.Language) (Entry, bool) {
	e, ok := registry[lang]
	return e, ok
}
