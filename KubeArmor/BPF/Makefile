ifeq (,$(KRNDIR))
KRNVER = $(shell uname -r)
ifneq (,$(wildcard /etc/redhat-release))
	KRNDIR = /usr/src/$(KRNVER)
else
	KRNDIR = /usr/src/linux-headers-$(KRNVER)
endif
endif
LIBBPF = $(CURDIR)/libbpf

CL  = clang
CC  = gcc
Q   = @

ifeq ($(V),1)
  Q =
endif

# shamelessly copied from kernel's samples/bpf/Makefile
KF = -I$(KRNDIR)/arch/x86/include -I$(KRNDIR)/arch/x86/include/generated  \
	 -I$(KRNDIR)/include -I$(KRNDIR)/arch/x86/include/uapi \
	 -I$(KRNDIR)/arch/x86/include/generated/uapi -I$(KRNDIR)/include/uapi \
	 -I$(KRNDIR)/include/generated/uapi \
	 -I$(LIBBPF)/src \
	 -include $(KRNDIR)/include/linux/kconfig.h \
	 -D__KERNEL__ \
	 -D__BPF_TRACING__ \
	 -D__TARGET_ARCH_x86 \
	 -Wunused \
	 -Wno-frame-address \
	 -Wno-unused-value \
	 -Wno-unknown-warning-option \
	 -Wno-pragma-once-outside-header \
	 -Wno-pointer-sign \
	 -Wno-gnu-variable-sized-type-not-at-end \
	 -Wno-deprecated-declarations \
	 -Wno-compare-distinct-pointer-types \
	 -Wno-address-of-packed-member \
	 -fno-stack-protector \
	 -fno-jump-tables \
	 -fno-unwind-tables \
	 -fno-asynchronous-unwind-tables \
	 -xc -O2 -g -emit-llvm

SRCDIR=$(CURDIR)

SRCS_KERN:=$(wildcard $(SRCDIR)/*.c)
SRCN:=$(notdir $(SRCS_KERN))
SYSMONITOR = $(CURDIR)/system_monitor.c

RED=\033[0;31m
GREEN=\033[0;32m
CYAN=\033[0;36m
NC=\033[0m

.PHONY: all
all: chkdir system_monitor.bpf.o system_monitor.container.bpf.o system_monitor.host.bpf.o

.PHONY: chkdir
chkdir:
ifeq (,$(wildcard $(KRNDIR)/Kconfig))
	@echo "Your kernel path[$(RED)$(KRNDIR)$(NC)] is incorrect. Use 'make KRNDIR=[KERNEL-SRC-PATH]'."
	Quitting abnormally
endif
ifeq (,$(wildcard $(LIBBPF)/src/libbpf.c))
	git submodule update --init --recursive
endif
ifeq (,$(wildcard $(LIBBPF)/src/libbpf.a))
	make -C $(LIBBPF)/src
endif

system_monitor.bpf.o: $(SYSMONITOR)
	@echo "Compiling eBPF bytecode: $(GREEN)$@$(NC) ..."
	$(Q)$(CL) $(KF) -DMONITOR_HOST_AND_CONTAINER -c $< -o -| llc -march=bpf -mcpu=probe -filetype=obj -o $@

system_monitor.container.bpf.o: $(SYSMONITOR)
	@echo "Compiling eBPF bytecode: $(GREEN)$@$(NC) ..."
	$(Q)$(CL) $(KF) -c $< -o -| llc -march=bpf -mcpu=probe -filetype=obj -o $@

system_monitor.host.bpf.o: $(SYSMONITOR)
	@echo "Compiling eBPF bytecode: $(GREEN)$@$(NC) ..."
	$(Q)$(CL) $(KF) -DMONITOR_HOST -c $< -o -| llc -march=bpf -mcpu=probe -filetype=obj -o $@

# cleanup
clean:
	$(Q)rm -rf *.o
