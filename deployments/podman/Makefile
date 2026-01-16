# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

# Go binaries to build
DEPLOYHOOK_SRC := DeployHook/main.go
DEPLOYHOOK_BIN := ./deployHook

HOOK_SRC := Hook/main.go Hook/podman.go
HOOK_BIN := ./hook

.PHONY: all build deploy clean

all: build

# Build all binaries
build: $(DEPLOYHOOK_BIN) $(HOOK_BIN)

# Build deployHook binary
$(DEPLOYHOOK_BIN): $(DEPLOYHOOK_SRC)
	@echo "[INFO] Building deployHook binary..."
	go build -o $@ $<

# Build hook binary (multiple source files)
$(HOOK_BIN): $(HOOK_SRC)
	@echo "[INFO] Building hook binary..."
	go build -o $@ $(HOOK_SRC)

# Deploy the Podman hook by running deployHook
deploy: build
	@echo "[INFO] Deploying Podman hook..."
	./$(DEPLOYHOOK_BIN)
