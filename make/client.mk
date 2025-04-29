

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

.PHONY: macos-sign
macos-sign:
	codesign --deep \
         --options runtime \
         --timestamp \
         --sign "Developer ID Application: NE43 INC (L2W77ZPF94)" \
		 $$(scripts/gowhere.sh)/foks

.PHONY: deb-arm64
deb-arm64: build/foks.linux-arm64.stripped
	./scripts/build-deb.sh -p arm64

.PHONY: deb-amd64
deb-amd64: build/foks.linux-amd64.stripped
	./scripts/build-deb.sh -p amd64

.PHONY: deb
deb: deb-arm64 deb-amd64
	@echo "Debian packages are ready in the build directory"

.PHONY: macos-verify
macos-verify:
	codesign --verify --deep --strict --verbose=2 $$(scripts/gowhere.sh)/foks
	codesign -dvv $$(scripts/gowhere.sh)/foks

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