.PHONY: test lint vuln cover tag-check clean

GO ?= go
SUBMODULES := storage-sdk manifest

test:
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...
	@for m in $(SUBMODULES); do \
		echo "→ submodule: $$m"; \
		(cd $$m && $(GO) test -race ./...) || exit 1; \
	done

lint:
	golangci-lint run --timeout 5m ./...
	@for m in $(SUBMODULES); do \
		echo "→ submodule: $$m"; \
		(cd $$m && golangci-lint run --timeout 5m ./...) || exit 1; \
	done

vuln:
	govulncheck ./...
	@for m in $(SUBMODULES); do \
		echo "→ submodule: $$m"; \
		(cd $$m && govulncheck ./...) || exit 1; \
	done

cover: test
	$(GO) tool cover -func=coverage.out | tail -1
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "→ open coverage.html"

# Verify proposed tag against go.mod major-version rules.
# Usage: make tag-check TAG=v0.1.0
tag-check:
	@test -n "$(TAG)" || (echo "Usage: make tag-check TAG=vX.Y.Z" && exit 1)
	@TAG_MAJOR=$$(echo "$(TAG)" | sed -E 's/^v([0-9]+).*/\1/'); \
	MOD=$$($(GO) list -m); \
	if [ "$$TAG_MAJOR" -ge 2 ]; then \
		echo "$$MOD" | grep -qE "/v$$TAG_MAJOR$$" || \
			(echo "ERROR: module path $$MOD must end /v$$TAG_MAJOR for tag $(TAG)" && exit 1); \
	fi; \
	echo "Tag $(TAG) compatible with module $$MOD"

clean:
	rm -f coverage.out coverage.html
	@for m in $(SUBMODULES); do (cd $$m && rm -f coverage.out coverage.html); done
