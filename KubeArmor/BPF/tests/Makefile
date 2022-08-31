# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Authors of KubeArmor


include ../Makefile.vars

LIBBPF = $(CURDIR)/../libbpf
VMLINUX = $(CURDIR)/../

Cfiles =  $(wildcard checks/*.c)
files = $(Cfiles:.c=)

.PHONY: all
all: compile-all syscheck check

syscheck: main.go
	@echo "Compiling $(GREEN)$@$(NC) ..."
	@[ -x "`which go 2>/dev/null`" ] && go build -o $@ $< || [ -x "./syscheck" ] || echo "Golang was not found in your system please install it to proceed"

.PHONY: compile-all
compile-all: checks/*.c
	@for i in $(files) ; do \
	echo "Compiling eBPF bytecode: $(GREEN)$$i.c$(NC) ..." && \
	$(CL) $(KF) -DMONITOR_HOST_AND_CONTAINER -c $$i.c -o -| llc -march=bpf -mcpu=probe -filetype=obj -o $$i.bpf.o;\
	done

.PHONY: check
check: checksyscall.sh syscheck
	@touch ignore.lst
	@touch cflags.lst
	@for i in $(files); do \
	echo "Checking syscall $(GREEN)$$i$(NC)" &&\
	chmod +x checksyscall.sh &&\
	./checksyscall.sh $$i;\
	done
	@mv ignore.lst cflags.lst ../

# clean up
clean:
	@[ -x "`which go 2>/dev/null`" ] && rm syscheck || true
	$(Q)rm -rf checks/*.o ../ignore.lst ignore.lst cflags.lst ../cflags.lst
