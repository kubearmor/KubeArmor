ifeq (,$(KRNDIR))
KRNVER = $(shell uname -r)
KRNDIR = /usr/src/linux-headers-$(KRNVER)
endif
LIBBPF = $(CURDIR)/libbpf

CL  = clang
CC  = gcc
Q   = @

ifeq ($(V),1)
  Q =
endif

# shamelessly copied from kernel's samples/bpf/Makefile
KF = -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/9/include \
	 -I$(KRNDIR)/arch/x86/include -I$(KRNDIR)/arch/x86/include/generated  \
	 -I$(KRNDIR)/include -I$(KRNDIR)/arch/x86/include/uapi \
	 -I$(KRNDIR)/arch/x86/include/generated/uapi -I$(KRNDIR)/include/uapi \
	 -I$(KRNDIR)/include/generated/uapi \
	 -I$(LIBBPF)/src \
	 -I/usr/lib/gcc/x86_64-alpine-linux-musl/10.3.1/include \
	 -I/usr/lib/gcc/x86_64-linux-gnu/7/include \
	 -include $(KRNDIR)/include/linux/kconfig.h \
	 -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
	 -D__TARGET_ARCH_x86 -Wno-compare-distinct-pointer-types \
	 -Wno-gnu-variable-sized-type-not-at-end \
	 -Wno-address-of-packed-member -Wno-tautological-compare \
	 -Wno-unknown-warning-option  \
	 -fno-stack-protector \
	 -O2 -emit-llvm

SRCDIR=$(CURDIR)

SRCS_KERN:=$(wildcard $(SRCDIR)/*.c)
SRCN:=$(notdir $(SRCS_KERN))
SYSMONITOR = $(CURDIR)/system_monitor.c

# vpath %.c $(SRCDIR)

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
