.PHONY: build
build:
	@go mod tidy
	@ginkgo -r --flake-attempts=5 --timeout=30m

.PHONY: test
test:
	@ginkgo -r
