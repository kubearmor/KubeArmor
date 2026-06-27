include Makefile.vars

.PHONY: all
all: kernel_headers libbpf system_monitor.bpf.o

.PHONY: kernel_headers
kernel_headers:
ifeq ($(BTF_SUPPORTED),1)
	@echo "$(GREEN)Kernel BTF information found$(NC)"
	@echo "Generating vmlinux.h for kernel $(KRNV_X).$(KRNV_Y).$(KRNV_Z)"
	$(Q)bpftool btf dump file $(KRBTF) format c > $(VMLINUX)/vmlinux.h
else
	@echo "$(RED)Kernel BTF information not found$(NC)"
	@echo "Trying to use kernel headers present in the host"
ifeq (,$(wildcard $(KRNDIR)/Kconfig))
	@echo "$(RED)Auto-detected kernel headers path [$(KRNDIR)] is incorrect.$(NC) Use 'make KRNDIR=[KERNEL-SRC-PATH]'."
	Quitting
else
	@echo "$(GREEN)Using kernel headers at $(KRNDIR)$(NC)"
endif
endif

.PHONY: libbpf
libbpf:
ifeq (,$(wildcard $(LIBBPF)/src/libbpf.c))
	$(Q)git submodule update --init --recursive
endif
ifeq (,$(wildcard $(LIBBPF)/src/libbpf.a))
	$(Q)make -C $(LIBBPF)/src
endif

# Modern single-step BPF compilation pipeline.
# 'clang -target bpf' compiles directly to BPF bytecode with CO-RE
# relocation support. This replaces the legacy multi-stage pipeline
# (clang | opt | llvm-dis | llc) 

system_monitor.bpf.o: $(SYSMONITOR) $(VMLINUX_H)
	@echo "Compiling eBPF bytecode: $(GREEN)$@$(NC) ..."
	$(Q)$(CL) $(KF) -c $< -o $@

.PHONY: clean
clean:
	$(Q)rm -rf *.o $(VMLINUX)/vmlinux.h

.PHONY: clean-all
clean-all: clean
	$(Q)make clean -C $(LIBBPF)/src
