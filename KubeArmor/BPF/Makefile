# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

#
# This Makefile was inspired by three libbpf related Makefiles:
#
# libbpf-bootstrap
# https://github.com/libbpf/libbpf-bootstrap/blob/a4169a2108fe1ab812e33471e0fcab214fde73a9/examples/c/Makefile
#
# libbpfgo
# https://github.com/aquasecurity/libbpfgo/blob/a68363581fcf8cb11039cec6f9d34338ef4393a9/Makefile
#
# linux kernel
# https://github.com/torvalds/linux/blob/d5ad8ec3cfb56a017de6a784835666475b4be349/tools/testing/selftests/bpf/Makefile
#

ifeq ($(V), 1)
	Q =	
else
	Q = @
endif

.PHONY: all
all: bpfobj system_monitor_host.bpf.o system_monitor_host_and_container.bpf.o

# bpf objects

CLANG      = clang
CLANGFLAGS = -g -O2 -c -target bpf -MMD -MP
CURDIR     = $(shell pwd)
CLANGINC   = $(CURDIR)/include
BPFOBJDIR  = $(CURDIR)/objs
SYSMONITOR = $(CURDIR)/system_monitor.bpf.c
BPFS_C     = $(wildcard *.bpf.c)
BPFS_O     = $(addprefix $(BPFOBJDIR)/, $(BPFS_C:.c=.o))
BPFS_D     = $(patsubst %.o, %.d, $(BPFS_O))

.PHONY: bpfobj
bpfobj: $(BPFS_O)

-include $(BPFS_D)

$(BPFOBJDIR)/%.o: %.c | $(BPFOBJDIR)
	$(info INFO: compiling bpf object $@)
	$(Q)$(CLANG) $(CLANGFLAGS) -I $(CLANGINC) -o $@ $<

system_monitor_host.bpf.o: $(SYSMONITOR) | $(BPFOBJDIR)
	$(info INFO: compiling bpf object $@)
	$(Q)$(CLANG) $(CLANGFLAGS) -DMONITOR_HOST -I $(CLANGINC) -o $(BPFOBJDIR)/$@ $<

system_monitor_host_and_container.bpf.o: $(SYSMONITOR) | $(BPFOBJDIR)
	$(info INFO: compiling bpf object $@)
	$(Q)$(CLANG) $(CLANGFLAGS) -DMONITOR_HOST_AND_CONTAINER -I $(CLANGINC) -o $(BPFOBJDIR)/$@ $<

# output

$(BPFOBJDIR):
	$(Q)mkdir -p $@

# cleanup

clean:
	$(Q)rm -rf $(BPFOBJDIR)
