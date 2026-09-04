# Secscantool

A single cross-platform CLI with two independent scan modes:

- `secscantool scan <path>` — code-level (SAST) and dependency
  vulnerability scanning of a local project. **secscantool never builds a
  Docker image itself.**
- `secscantool scan image <name>` — vulnerability scanning of an existing
  Docker image (yours, already built, or one from a registry) via Trivy;
  pulls it first if it isn't already present locally.

Either mode writes the same unified report (JSON, Markdown, HTML, PDF).
`--only code` / `--only dependency` on `scan` let you run just one stage
instead of both.

No AI/LLM is involved anywhere: it deterministically orchestrates
well-known open-source scanners and normalizes their output.

## Supported today

| Language | Code-level (SAST) | Dependency scan |
|---|---|---|
| Go | [gosec](https://github.com/securego/gosec) | [govulncheck](https://golang.org/x/vuln/cmd/govulncheck) |
| Node.js | [semgrep](https://semgrep.dev) | `npm audit` |
| Docker image (`scan image`) | — | [Trivy](https://github.com/aquasecurity/trivy) |

More languages are added by writing one adapter package under
`internal/scanner/` and registering it in `internal/registry/registry.go` —
no other code changes.

## How tool installation works

`secscantool` itself ships with **none of the above scanners bundled**. The
first time a scan actually needs one, it checks whether it's already
installed and, if not, installs it automatically:

- **Go tools** (`gosec`, `govulncheck`): `go install <module>@latest`
- **semgrep**: installed into a small dedicated virtualenv under your user
  cache dir (`~/.cache/secscantool/semgrep-venv` on Linux,
  `~/Library/Caches/secscantool/semgrep-venv` on macOS) via `pip install
  semgrep` — this avoids touching your system Python packages, and sidesteps
  the fact that the `semgrep` npm package is an unrelated abandoned stub, not
  the real tool.
- **trivy**: downloaded as a prebuilt release archive from GitHub, verified
  against trivy's own published sha256 checksums, and extracted into
  `~/.cache/secscantool/bin` (or the platform equivalent) — not `go install`,
  since trivy's own docs call that unsupported, and in practice it can fail
  to even compile against a given Go toolchain.
- **npm audit** needs no separate install — it ships with npm itself.

What `secscantool` will **not** install for you is the underlying language
runtime: the Go toolchain, Node.js/npm, Python 3 (for semgrep), and Docker
are all things you install yourself. Run `secscantool doctor` to see exactly
what's present and what's missing before scanning.

## Install

```sh
go build -o secscantool ./cmd/secscantool          # local dev build, unversioned
make cross                                          # raw binaries for every OS/arch, into dist/
make release version=1.1.1                          # full packaged release, see below
```

### `make release version=1.1.1` — what it builds

| Platform | Artifact | Built by |
|---|---|---|
| Linux (amd64, arm64) | `secscantool-linux-<arch>.tar.gz` (raw binary) | `make archives` |
| Linux (amd64, arm64) | `secscantool_<version>_<arch>.deb` | `make packages` (via [nfpm](https://nfpm.goreleaser.com)) |
| Linux (amd64, arm64) | `secscantool_<version>_<arch>.rpm` | `make packages` (via nfpm) |
| macOS (amd64, arm64) | `secscantool-darwin-<arch>.tar.gz` (raw binary) | `make archives` |
| macOS (amd64, arm64) | `secscantool_<version>_darwin-<arch>.dmg` | `make dmg` (via `hdiutil`, macOS-only) |
| Windows (amd64, arm64) | `secscantool-windows-<arch>.exe` + matching `.zip` | `make archives` |
| Windows (amd64) | `secscantool_<version>_amd64.msi` | `make msi` — **Windows-only, see below** |
| all of the above | `dist/checksums.txt` (sha256 of every artifact) | `make checksums` |

Every binary has its version baked in via `-ldflags -X main.version=...` (`secscantool version` prints it).

`make release` builds everything above **except the `.msi`**, because the
WiX Toolset (the MSI compiler) only runs on Windows. The `.deb`/`.rpm`
(via nfpm, a pure-Go tool) and the `.dmg` (via macOS's built-in `hdiutil`)
build and were verified on this machine; the `.msi` needs a separate step:

```sh
# On a Windows machine (or a Windows CI runner) with WiX installed:
dotnet tool install --global wix
make msi version=1.1.1   # reads dist/secscantool-windows-amd64.exe, writes the .msi
```

`packaging/secscantool.wxs` (the WiX source) installs to
`Program Files\secscantool\secscantool.exe` and adds that folder to the
system `PATH`. It was written against the current WiX v4/v5 schema and
reviewed for correctness, but — since WiX can't run outside Windows —
**it has not actually been built or installed yet**; treat it as unverified
until it's been through `make msi` once on real Windows.

Building `.deb`/`.rpm` requires [nfpm](https://nfpm.goreleaser.com) on your
PATH: `go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest`.

## Usage

```sh
secscantool doctor                          # check prerequisites + scanner tool status

secscantool scan .                          # code + dependency scan of the current directory
secscantool scan ../my-api -o ./scan-results
secscantool scan ../my-api --only code       # code scan only (skip dependencies)
secscantool scan ../my-api --only dependency # dependency scan only (skip code)

secscantool scan image myapp:latest         # scan an image you already built
secscantool scan image node:18-alpine       # pulls it first, since it's not local
```

## Report format

Every scan writes the same findings in four formats to the output
directory (`--output` if given, otherwise `./secscantool-report` in
whatever directory you ran the command from — not inside the scanned
project):

| File | For |
|---|---|
| `report.json` | machine-readable — CI pipelines, custom tooling, diffing runs |
| `report.md` | plain-text reading, pasting into a PR/issue |
| `report.html` | browsing locally, works fully offline, no external assets |
| `report.pdf` | sharing/archiving — a fixed, printable snapshot of the same findings |

All four are built from the same data and organized the same way, meant to
be handed to a developer or a stakeholder as-is:

1. **Header** — target, generation time, total finding count
2. **Executive Summary** — a Critical/High/Medium/Low/Info count strip plus
   one auto-generated sentence ("4 high severity issue(s) should be
   prioritized.")
3. **One findings table per module** (and one for the container image, if
   scanned), worst severity first, with a single S.No sequence numbered
   across the whole report — a stakeholder can reference "finding #14"
   unambiguously. Columns:

   | # | Severity | CVE / Rule ID | Issue | Location / Package | Description | Fix Suggestion |
   |---|---|---|---|---|---|---|

   - **Severity** — a colored badge plus its numeric rank (Critical=5 … Info=1)
   - **CVE / Rule ID** — the finding's own identifier: a CVE/GHSA/OSV id for
     dependency and container findings, or the scanner's own rule id (gosec's
     `G204`, semgrep's check id) for code findings — linked to the advisory
     or rule docs when the tool provides a URL
   - **Location / Package** — `file:line` for code findings; `package@version
     -> fixed-version` for dependency/container findings
   - **Fix Suggestion** — a concrete command to run (`npm audit fix`,
     `go get <module>@<fixed-version> && go mod tidy`, an upgrade path for a
     container base image, etc.), not just a description of the problem

`report.html` additionally color-codes every row and is fully self-contained
(no external assets, works offline, prints cleanly). `report.pdf` renders
the same table in landscape for sharing/archiving as a fixed snapshot.
`report.md` uses GitHub-flavored tables, so it renders correctly pasted into
a PR/issue or viewed on GitHub/GitLab directly. `report.json` carries every
field above (plus the full, untruncated description) for CI pipelines and
custom tooling.

A terminal summary table (counts per module/container by severity) is
always printed too, independent of which report files get written.

## Prerequisites by stage

| Stage | You must install | secscantool auto-installs |
|---|---|---|
| Go project | Go toolchain | gosec, govulncheck |
| Node.js project | Node.js + npm | — (npm audit ships with npm) |
| Node.js code scan | Python 3 | semgrep (into its own venv) |
| `scan image` | Docker (daemon running) | trivy |
