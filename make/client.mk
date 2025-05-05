

## 
##-----------------------------------------------------------------------
## Rules for building the FOKS client -- the most common operations!
##

.PHONY: client
client:
	(cd client/foks && CGO_ENABLED=1 go install)
	@echo "Client binary is ready: $$(scripts/gowhere.sh)/foks"


client-proto: proto client
full: client-proto

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

.PHONY: macos-arm64-zip-release
darwin-arm64-zip-release: build/darwin-arm64/foks.zip
	./scripts/macos-notary.bash $<
	@echo "macOS arm64 release is ready: $<"
	./scripts/macos-verify.bash $<

.PHONY: macos-arm64-zip-release-verify
darwin-arm64-zip-release-verify:
	./scripts/macos-verify.bash build/darwin-arm64/foks.zip

.PHONY: macos-amd64-zip-release
darwin-amd64-zip-release: build/darwin-amd64/foks.zip
	./scripts/macos-notary.bash $<
	@echo "macOS amd64 release is ready: $<"
	./scripts/macos-verify.bash $<

.PHONY: macos-amd64-zip-release-verify
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

##
##-----------------------------------------------------------------------
##

.stamps/npm-install:
	npm i
	mkdir -p .stamps
	date > .stamps/npm-install

.PHONY: proto
proto: .stamps/npm-install
	(cd proto-src && go run ../tools/snowp-checker)
	go generate ./...

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
build/darwin-amd64/foks.zip: build/darwin-amd64/foks
	./scripts/macos-sign.bash $<
	./scripts/macos-ditto.bash $$(dirname $<)

build/darwin-arm64/foks: proto
	./scripts/macos-compile.bash -p arm64 -s
build/darwin-arm64/foks.zip: build/darwin-arm64/foks
	./scripts/macos-sign.bash $<
	./scripts/macos-ditto.bash $$(dirname $<)

