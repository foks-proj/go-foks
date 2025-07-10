

BIN_DIR = ./bin
FRONTEND_DIR = server/web/frontend
TEMPL_DIR = server/web/templates
STATIC_DIR = server/web/static
TAILWIND_BIN = ./node_modules/.bin/tailwindcss
UGLIFY_BIN = ./node_modules/.bin/uglifyjs
HTMX_DIST=$(FRONTEND_DIR)/node_modules/htmx.org/dist
STATIC_JS_DIR=$(STATIC_DIR)/js

.stamps/srv-npm-install:
	(cd $(FRONTEND_DIR) && npm i)
	date > .stamps/srv-npm-install

.PHONY: srv-setup
srv-setup: .stamps/srv-npm-install

.PHONY: srv-templ-build
srv-templ-build:
	(cd $(TEMPL_DIR) && go tool templ generate)

.PHONY: srv-templ-watch
srv-templ-watch:
	(cd $(TEMPL_DIR) && go tool templ generate --watch)

.PHONY: srv-tailwind-watch
srv-tailwind-watch:
	(cd $(FRONTEND_DIR) && \
	  mkdir -p ../static/css && \
	  $(TAILWIND_BIN) -i ./css/input.css -o ../static/css/style.css --watch)

.PHONY: srv-tailwind-build
srv-tailwind-build: .stamps/srv-npm-install
	(cd $(FRONTEND_DIR) && \
	  mkdir -p ../static/css && \
	  $(TAILWIND_BIN) -i ./css/input.css -o ../static/css/style.min.css --minify && \
	  $(TAILWIND_BIN) -i ./css/input.css -o ../static/css/style.css )

.PHONY: srv-js-build
srv-js-build: .stamps/srv-npm-install
	(cd $(FRONTEND_DIR) && \
		$(UGLIFY_BIN) -c < ../static/js/foks.js > ../static/js/foks.min.js )

.PHONY: srv-htmx-build
srv-htmx-build:
	(mkdir -p $(STATIC_JS_DIR) &&  \
	 (diff -q $(HTMX_DIST)/htmx.js $(STATIC_JS_DIR)/htmx.js || \
	  cp -f $(HTMX_DIST)/htmx.js $(STATIC_JS_DIR)/htmx.js) && \
	 (diff -q $(HTMX_DIST)/htmx.min.js $(STATIC_JS_DIR)/htmx.min.js || \
	  cp -f $(HTMX_DIST)/htmx.min.js $(STATIC_JS_DIR)/ ) )

.PHONY: srv-assets
srv-assets: srv-tailwind-build srv-templ-build srv-js-build srv-htmx-build

.PHONY: srv-install
srv-install: srv-assets
	@echo "Installing server with GOBIN=$(GOBIN)"
	( \
		cd server/foks-server && \
		CGO_ENABLED=0 \
			go install \
			-ldflags="-X main.LinkerVersion=$$(git describe --tags --always)" \
	)

.PHONY: ghcr-login
ghcr-login:
	foks kv get --team build.server /secrets/github/classic-access-token-ghcr - | \
		docker login ghcr.io --username maxtaco --password-stdin


.PHONY: foks-server-docker-image-latest
foks-server-docker-image-latest:
	docker buildx build \
		--build-arg VERSION=$$(git describe --tags --always) \
		-f dockerfiles/foks-server.dev \
		-t foks-server:latest \
		--platform=linux/arm64,linux/amd64 .

.PHONY: foks-server-docker-push
foks-server-docker-push: ghcr-login foks-server-docker-image-latest foks-tool-docker-image-latest
	docker tag foks-server:latest ghcr.io/foks-proj/foks-server:latest
	docker push ghcr.io/foks-proj/foks-server:latest
	docker tag foks-tool:latest ghcr.io/foks-proj/foks-tool:latest
	docker push ghcr.io/foks-proj/foks-tool:latest

.PHONY: foks-tool-linux
foks-tool-linux: build/foks-tool.linux.arm64.gz build/foks-tool.linux.amd64.gz

.PHONY: foks-tool-docker-image-latest
foks-tool-docker-image-latest:
	docker buildx build \
		--build-arg VERSION=$$(git describe --tags --always) \
		-f dockerfiles/foks-tool.dev \
		-t foks-tool:latest \
		--platform=linux/arm64,linux/amd64 .

.PHONY: build/foks-tool.linux.arm64.gz
build/foks-tool.linux.arm64.gz:
	bash -x scripts/cross-compile-foks-tool.bash -p arm64 -s

.PHONY: build/foks-tool.linux.amd64.gz
build/foks-tool.linux.amd64.gz:
	bash -x scripts/cross-compile-foks-tool.bash -p amd64 -s

.PHONY: foks-tool-gh-push
foks-tool-gh-push: foks-tool-linux
	gh release upload \
		--clobber $$(git describe --tags --abbrev=0) \
		build/foks-tool.linux.arm64.gz \
		build/foks-tool.linux.amd64.gz

.PHONY: foks-server-release
foks-server-release: foks-tool-gh-push foks-server-docker-push