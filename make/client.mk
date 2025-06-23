

## 
##-----------------------------------------------------------------------
## Rules for building the FOKS client -- the most common operations!
##

.PHONY: client
client:
	(cd client/foks && CGO_ENABLED=1 go install)
	@echo "Client binary is ready: $$(scripts/gowhere.sh)/foks"

.PHONY: client-signed
client-signed:
	./scripts/macos-compile.bash -l 
	./scripts/macos-sign.bash $$(scripts/gowhere.sh)/foks
	@echo "Signed client binary is ready: $$(scripts/gowhere.sh)/foks"

client-proto: proto client
full: client-proto

.PHONY: client-win-amd64
client-win-amd64:
	./scripts/win-native-compile.bash -p amd64 -l
	@echo "Client binary is ready: $$(scripts/gowhere.sh)/foks.exe"

.PHONY: client-linux-arm64
client-linux-arm64: build/foks.linux-arm64
	@echo "Client binary for linux/arm64 is ready: $<"

.PHONY: client-linux-arm64-stripped
client-linux-arm64-stripped: build/foks.linux-arm64.stripped
	@echo "Client binary for linux/arm64 is ready: $<"

.PHONY: client-linux-amd64
client-linux-amd64: build/foks.linux-amd64
	@echo "Client binary for linux/amd64 is ready: $<"

.PHONY: git-link
git-link:
	./scripts/git-link.sh

.PHONY: ci
ci:
	bash ci.bash

.PHONY: ci-yubi-destructive
ci-yubi-destructive:
	bash ci.bash --yubi-destructive

.PHONY: brew-arm64
brew-arm64: build/darwin-brew-arm64/foks.zip
	./scripts/macos-notary.bash $<
	@echo "brew arm64 release is ready: $<"
	./scripts/macos-verify.bash $<

.PHONY: brew-amd64
brew-amd64: build/darwin-brew-amd64/foks.zip
	./scripts/macos-notary.bash $<
	@echo "brew amd64 release is ready: $<"
	./scripts/macos-verify.bash $<

.PHONY: darwin-arm64-zip-release
darwin-arm64-zip-release: build/darwin-arm64/foks.zip
	./scripts/macos-notary.bash $<
	@echo "macOS arm64 release is ready: $<"
	./scripts/macos-verify.bash $<

.PHONY: darwin-arm64-zip-release-verify
darwin-arm64-zip-release-verify:
	./scripts/macos-verify.bash build/darwin-arm64/foks.zip

.PHONY: darwin-amd64-zip-release
darwin-amd64-zip-release: build/darwin-amd64/foks.zip
	./scripts/macos-notary.bash $<
	@echo "macOS amd64 release is ready: $<"
	./scripts/macos-verify.bash $<

.PHONY: darwin-amd64-zip-release-verify
darwin-amd64-zip-release-verify:
	./scripts/macos-verify.bash build/darwin-amd64/foks.zip

.PHONY: deb-arm64
deb-arm64: build/foks.linux-arm64.stripped
	./scripts/build-deb.sh -p arm64

.PHONY: deb-amd64
deb-amd64: build/foks.linux-amd64.stripped
	./scripts/build-deb.sh -p amd64

.PHONY: deb
deb: deb-arm64 deb-amd64
	@echo "Debian packages are ready in the build directory"

.PHONY: rpm-arm64
rpm-arm64:
	./scripts/build-rpm.sh -p arm64

.PHONY: rpm-amd64
rpm-amd64:
	./scripts/build-rpm.sh -p amd64

.PHONY: rpm
rpm: rpm-arm64 rpm-amd64
	@echo "RPM packages are ready in the build directory"

.PHONY: darwin-zip
darwin-zip: darwin-arm64-zip-release darwin-amd64-zip-release
	@echo "macOS zip packages are ready in the build directory"

.PHONY: brew
brew: brew-arm64 brew-amd64
	@echo "Homebrew zip packages are ready in the build directory"

.PHONY: choco
choco: choco-amd64 choco-x86
	@echo "Chocolatey windows packages are ready in the build directory"

.PHONY: choco-x86
choco-x86: proto
	./scripts/cross-compile-win.bash -p win-x86 -sc

.PHONY: choco-amd64
choco-amd64: proto
	./scripts/cross-compile-win.bash -p win-amd64 -sc

.PHONY: musl-arm64
musl-arm64:
	./scripts/linux-musl.bash -p arm64

.PHONY: musl-amd64
musl-amd64:
	./scripts/linux-musl.bash -p amd64

.PHONY: musl
musl: musl-arm64 musl-amd64
	@echo "Musl binaries are ready in the build directory"

.PHONY: release-all
release-all: deb rpm darwin-zip brew musl
	@echo "All release packages are ready in the build directory"

##
##-----------------------------------------------------------------------
##

.PHONY: proto
proto: 
	go generate ./...
	(cd proto-src && go run ../tools/snowp-checker)

build/foks.linux-arm64: proto
	./scripts/cross-compile.sh -p linux-arm64

build/foks.linux-arm64.stripped: proto
	./scripts/cross-compile.sh -p linux-arm64 -s

build/foks.linux-amd64: proto
	./scripts/cross-compile.sh -p linux-amd64

build/foks.linux-amd64.stripped: proto
	./scripts/cross-compile.sh -p linux-amd64 -s


build/darwin-amd64/foks: proto
	./scripts/macos-compile.bash -p amd64 -s
build/darwin-brew-amd64/foks: proto
	./scripts/macos-compile.bash -p amd64 -s -b
build/darwin-amd64/foks.zip: build/darwin-amd64/foks
	./scripts/macos-sign.bash $<
	./scripts/macos-ditto.bash $$(dirname $<)
build/darwin-brew-amd64/foks.zip: build/darwin-brew-amd64/foks
	./scripts/macos-sign.bash $<
	./scripts/macos-ditto.bash $$(dirname $<)

build/darwin-brew-arm64/foks: proto
	./scripts/macos-compile.bash -p arm64 -s -b
build/darwin-arm64/foks: proto
	./scripts/macos-compile.bash -p arm64 -s
build/darwin-arm64/foks.zip: build/darwin-arm64/foks
	./scripts/macos-sign.bash $<
	./scripts/macos-ditto.bash $$(dirname $<)
build/darwin-brew-arm64/foks.zip: build/darwin-brew-arm64/foks
	./scripts/macos-sign.bash $<
	./scripts/macos-ditto.bash $$(dirname $<)

build/win-amd64/foks.exe: proto
	./scripts/win-cross-compile.bash -p amd64 -s
build/win-arm64/foks.exe: proto
	./scripts/win-cross-compile.bash -p arm64 -s
