# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Authors of KubeArmor

.PHONY: build
build:
	@go mod tidy
	@ginkgo -r --flake-attempts=5 --timeout=30m --skip-file=tests/systemd

.PHONY: test
test:
	@ginkgo -r
