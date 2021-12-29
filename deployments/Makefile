# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

CURDIR=$(shell pwd)

.PHONY: gen
gen: build
	./deploygen

.PHONY: build
build:
	cd $(CURDIR)
	go mod tidy
	go build -o deploygen

