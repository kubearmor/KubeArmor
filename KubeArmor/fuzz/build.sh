# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor
printf "package transform\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/KubeArmor/KubeArmor/register.go
go mod tidy
compile_native_go_fuzzer github.com/kubearmor/KubeArmor/KubeArmor/core FuzzContainerPolicy FuzzContainerPolicy
compile_native_go_fuzzer github.com/kubearmor/KubeArmor/KubeArmor/core FuzzHostPolicy FuzzHostPolicy

