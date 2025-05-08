

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
		CGO_ENABLED=1 go install \
	)

.PHONY: srv-dev
srv-dev:
	go tool air
