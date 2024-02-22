# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Authors of KubeArmor

.PHONY: build
build:
	@go mod tidy
	# run in two steps as syscall suite fails if run at the very end
	@ginkgo --vv --flake-attempts=10 --timeout=10m syscalls/
	@ginkgo -r --vv --flake-attempts=10 --timeout=30m --skip-package "syscalls"
.PHONY: test
test:
	@ginkgo -r -v