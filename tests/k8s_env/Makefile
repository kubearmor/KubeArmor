# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Authors of KubeArmor

.PHONY: build
build:
	@go mod tidy
	# run in two steps as syscall suite fails if run at the very end
	# see - https://github.com/kubearmor/KubeArmor/issues/1269
	@ginkgo --vv --flake-attempts=10 --timeout=15m syscalls/
	@ginkgo -r --vv --flake-attempts=10 --timeout=30m --skip-package "syscalls,networktests"
.PHONY: test
test:
	@ginkgo -r -v