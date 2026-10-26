# Common tasks. Run `make help` for a list.

# Tool versions, used here and in CI (which calls these targets).
SQLC_IMAGE ?= sqlc/sqlc:1.30.0
KUBECONFORM_IMAGE ?= ghcr.io/yannh/kubeconform:v0.8.0
AWS_CLI_IMAGE ?= amazon/aws-cli:2.38.5
GOVULNCHECK_VERSION ?= v1.9.0
# The tests' backing services run in their own compose project, on their own
# ports: a dev stack on the default ports stays untouched.
TEST_PROJECT ?= platypus-test
TEST_COMPOSE = docker compose -p $(TEST_PROJECT) -f docker-compose.yaml -f compose.test.yaml
TEST_DATABASE_URL ?= postgres://postgres:postgres@localhost:55433/postgres
TEST_AWS_ENDPOINT ?= http://localhost:54567

.PHONY: help
help: ## Show this help
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-22s %s\n", $$1, $$2}'

.PHONY: generate
generate: ## Regenerate database code (sqlc) and the configuration docs page
	docker run --rm -v "$(CURDIR)":/src -w /src/database $(SQLC_IMAGE) generate
	go generate ./...

.PHONY: generate-check
generate-check: generate ## Fail when generated code or docs are out of date
	git diff --exit-code -- internal/db internal/docs/pages

.PHONY: vendored-check
vendored-check: ## Fail when a vendored file (htmx) differs from its pinned checksum
	cd internal/web && shasum -a 256 -c vendored.sha256

.PHONY: build
build: ## Build the binary into bin/
	go build -trimpath -o bin/platypus ./cmd/platypus

.PHONY: test-deps
test-deps: ## Start the isolated test Postgres and AWS emulator (ports 55433/54567)
	$(TEST_COMPOSE) up -d postgres ministack

.PHONY: test-clean
test-clean: ## Stop the test stack and drop its data
	$(TEST_COMPOSE) down -v

.PHONY: test
test: ## Run all tests, including database and AWS emulator tests
	PLATYPUS_TEST_DATABASE_URL=$(TEST_DATABASE_URL) PLATYPUS_TEST_AWS_ENDPOINT=$(TEST_AWS_ENDPOINT) \
		go test -race -count=1 ./...

.PHONY: test-unit
test-unit: ## Run the tests that need neither Postgres nor the AWS emulator
	go test -race -count=1 ./...

.PHONY: sqlfluff
sqlfluff: ## Lint the sqlc queries with sqlfluff (Docker)
	./scripts/sqlfluff.sh

.PHONY: lint
lint: vulncheck ## Run golangci-lint and govulncheck
	golangci-lint run ./...

.PHONY: vulncheck
vulncheck: ## Check the code and its dependencies for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

.PHONY: dev
dev: ## Run platypus locally with docker-compose
	docker compose up --build

.PHONY: dev-reload
dev-reload: ## Rebuild web/worker and reload the templates (what a code change needs)
	docker compose up -d --build web worker
	# Templates are mounted but parsed at startup, and up -d leaves an
	# unchanged container running: restart so template edits are actually live.
	docker compose restart web worker
	# nginx resolves the web container's address once, at startup; a recreated
	# container gets a new one, so without this reload every page is a 502.
	docker compose restart dev-proxy
	@for _ in $$(seq 1 60); do \
		status=$$(curl -s -o /dev/null -w '%{http_code}' http://admin.localhost:8090/ || true); \
		case "$$status" in 2*|3*) echo "dev stack ready ($$status)"; exit 0;; esac; \
		sleep 1; \
	done; \
	echo "dev stack did not become ready" >&2; exit 1

.PHONY: dev-bootstrap-token
dev-bootstrap-token: ## Print the bootstrap token of the local stack (test mode only)
	@docker run --rm --network platypus_default \
		-e AWS_ACCESS_KEY_ID=test -e AWS_SECRET_ACCESS_KEY=test -e AWS_REGION=eu-west-1 \
		$(AWS_CLI_IMAGE) --endpoint-url http://ministack:4566 ssm get-parameter --with-decryption \
		--name /platypus/bootstrap-token --query Parameter.Value --output text

.PHONY: smoke
smoke: ## Start the compose stack from scratch and check platypus reaches the bootstrap page
	./scripts/smoke-test.sh

.PHONY: css
css: ## Rebuild the stylesheet from internal/web/static/css/*.css
	./scripts/build-css.sh

.PHONY: css-check
css-check: ## Fail when the stylesheet is not rebuilt from its parts
	@tmp=$$(mktemp); cat internal/web/static/css/*.css > $$tmp; \
	if ! cmp -s $$tmp internal/web/static/style.css; then \
		echo "style.css is stale: run make css" >&2; rm -f $$tmp; exit 1; \
	fi; rm -f $$tmp

.PHONY: e2e
e2e: ## Run the browser tests (Playwright in Docker) against a fresh stack
	./e2e/run.sh

.PHONY: verify
verify: generate-check vendored-check test sqlfluff css-check e2e ## Everything CI must pass before a change is done
	golangci-lint run ./...

.PHONY: visual
visual: ## Compare the UI against the committed visual baselines
	VISUAL=1 ./e2e/run.sh

.PHONY: visual-update
visual-update: ## Regenerate the visual baselines (review the diff before committing)
	VISUAL=1 VISUAL_UPDATE=1 ./e2e/run.sh

.PHONY: screenshots
screenshots: ## Capture documentation screenshots into docs/images
	DOCS_SHOTS=1 ./e2e/run.sh

.PHONY: guards-prove
guards-prove: ## Reintroduce known bugs and prove the guards catch each one
	./scripts/guards-prove.sh

.PHONY: helm-lint
helm-lint: ## Lint the Helm chart and validate it with every example in charts/platypus/ci
	for values in charts/platypus/ci/*.yaml; do \
		helm lint charts/platypus -f $$values || exit 1; \
		helm template platypus charts/platypus -f $$values | \
			docker run --rm -i $(KUBECONFORM_IMAGE) -strict -summary -ignore-missing-schemas - || exit 1; \
	done
