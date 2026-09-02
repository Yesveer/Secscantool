// Command secscantool is a cross-platform CLI that detects a project's
// language, runs code-level and dependency-level vulnerability scans, and
// (when a Dockerfile is present) builds and scans the container image —
// then writes one unified report. See root.go for the command tree.
package main

func main() {
	Execute()
}
