# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Authors of KubeArmor

.PHONY: build
build:
	@go mod tidy
	@ginkgo -r --flake-attempts=5 --timeout=30m

.PHONY: test
test:
	@go mod tidy
	@go get github.com/onsi/ginkgo/v2
	@ginkgo -r
