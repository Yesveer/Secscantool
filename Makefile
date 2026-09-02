BINARY := secscantool
PKG := ./cmd/secscantool
DIST := dist
PACKAGING := packaging

# `make release version=1.1.1` (or VERSION=1.1.1) sets the version embedded
# in every binary and stamped on every package.
VERSION ?= dev
ifdef version
VERSION := $(version)
endif

LDFLAGS := -s -w -X main.version=$(VERSION)

UNIX_PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64
WINDOWS_PLATFORMS := windows/amd64 windows/arm64
PLATFORMS := $(UNIX_PLATFORMS) $(WINDOWS_PLATFORMS)

.PHONY: build test vet cross release archives packages dmg msi checksums clean

## Local dev build (current OS/arch, unversioned).
build:
	go build -o $(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

## Cross-compile a raw binary for every supported OS/arch into dist/.
cross: $(PLATFORMS)

.PHONY: $(PLATFORMS)
$(PLATFORMS):
	$(eval OS := $(word 1,$(subst /, ,$@)))
	$(eval ARCH := $(word 2,$(subst /, ,$@)))
	$(eval EXT := $(if $(filter windows,$(OS)),.exe,))
	mkdir -p $(DIST)
	GOOS=$(OS) GOARCH=$(ARCH) go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-$(OS)-$(ARCH)$(EXT) $(PKG)

## Full release: versioned binaries + .tar.gz/.zip archives + .deb/.rpm + .dmg + checksums.
## Windows .msi is intentionally NOT built here -- see the `msi` target below.
release: clean cross archives packages dmg checksums
	@echo ""
	@echo "== secscantool $(VERSION) release built in $(DIST)/ =="
	@echo "Windows .msi installer is NOT built by this target (WiX only runs on Windows)."
	@echo "On a Windows machine (or a Windows CI runner) with the WiX Toolset installed, run:"
	@echo "    make msi version=$(VERSION)"
	@echo "using $(DIST)/$(BINARY)-windows-amd64.exe produced by this release as input."

## .tar.gz for macOS/Linux binaries, .zip for Windows binaries.
archives:
	@for p in $(subst /,-,$(UNIX_PLATFORMS)); do \
		tar -C $(DIST) -czf $(DIST)/$(BINARY)-$$p.tar.gz $(BINARY)-$$p; \
	done
	@for p in $(subst /,-,$(WINDOWS_PLATFORMS)); do \
		( cd $(DIST) && zip -q $(BINARY)-$$p.zip $(BINARY)-$$p.exe ); \
	done

## .deb and .rpm packages for linux/amd64 + linux/arm64, via nfpm.
## Install nfpm with: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
packages:
	@command -v nfpm >/dev/null || { echo "nfpm not found. Install with: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"; exit 1; }
	@for arch in amd64 arm64; do \
		sed -e "s|__ARCH__|$$arch|g" -e "s|__VERSION__|$(VERSION)|g" \
			-e "s|__BINARY_PATH__|$(DIST)/$(BINARY)-linux-$$arch|g" \
			$(PACKAGING)/nfpm.yaml > $(DIST)/.nfpm-$$arch.yaml; \
		nfpm package --config $(DIST)/.nfpm-$$arch.yaml --packager deb --target $(DIST)/$(BINARY)_$(VERSION)_$$arch.deb; \
		nfpm package --config $(DIST)/.nfpm-$$arch.yaml --packager rpm --target $(DIST)/$(BINARY)_$(VERSION)_$$arch.rpm; \
		rm -f $(DIST)/.nfpm-$$arch.yaml; \
	done

## macOS .dmg for darwin/amd64 + darwin/arm64. hdiutil is macOS-only, so this
## target is a no-op with a warning anywhere else.
dmg:
ifeq ($(shell uname),Darwin)
	@for arch in amd64 arm64; do \
		stage=$(DIST)/dmg-stage-$$arch; \
		rm -rf $$stage && mkdir -p $$stage; \
		cp $(DIST)/$(BINARY)-darwin-$$arch $$stage/$(BINARY); \
		cp README.md $$stage/ 2>/dev/null || true; \
		hdiutil create -volname "$(BINARY) $(VERSION)" -srcfolder $$stage -ov -format UDZO \
			$(DIST)/$(BINARY)_$(VERSION)_darwin-$$arch.dmg >/dev/null; \
		rm -rf $$stage; \
	done
else
	@echo "Skipping .dmg: hdiutil is macOS-only. Run 'make dmg' on macOS to build it."
endif

## Windows .msi installer via the WiX Toolset v4/v5. WiX only runs on
## Windows, so this target must be run there (or in Windows CI), after
## copying dist/secscantool-windows-amd64.exe from a release built anywhere.
## Install WiX with: dotnet tool install --global wix
msi:
	@command -v wix >/dev/null || { echo "wix not found. On Windows, install with: dotnet tool install --global wix"; exit 1; }
	wix build $(PACKAGING)/secscantool.wxs \
		-d Version=$(VERSION) \
		-d ExePath=$(DIST)/$(BINARY)-windows-amd64.exe \
		-arch x64 \
		-o $(DIST)/$(BINARY)_$(VERSION)_amd64.msi

## SHA256 checksums for every artifact in dist/, for release verification.
## The file list is captured before checksums.txt is created, so it never
## ends up hashing (an empty, not-yet-written copy of) itself.
checksums:
	@cd $(DIST) && files=$$(ls | grep -v '^checksums\.txt$$') && \
		( shasum -a 256 $$files 2>/dev/null || sha256sum $$files ) > checksums.txt

clean:
	rm -rf $(DIST) $(BINARY)
