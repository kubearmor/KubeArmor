include Makefile.vars

.PHONY: all
all: kernel_headers libbpf system_monitor.bpf.o system_monitor.container.bpf.o system_monitor.host.bpf.o

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

# below we use long chain of commands, clang | opt | llvm-dis | llc,
# to generate final object file. 'clang' compiles the source into IR
# with native target, e.g., x64, arm64, etc. 'opt' does bpf CORE IR builtin
# processing (llvm12) and IR optimizations. 'llvm-dis' converts
# 'opt' output to IR, and finally 'llc' generates bpf byte code.
# Ref https://elixir.bootlin.com/linux/v5.19.5/source/samples/bpf/Makefile#L439

system_monitor.bpf.o: $(SYSMONITOR) $(VMLINUX_H)
	@echo "Compiling eBPF bytecode: $(GREEN)$@$(NC) ..."
	$(Q)$(CL) $(KF) -DMONITOR_HOST_AND_CONTAINER -Xclang -disable-llvm-passes -c $< -o - | opt -O2 -mtriple=bpf-pc-linux | llvm-dis | llc -march=bpf -mcpu=probe -filetype=obj -o $@

system_monitor.container.bpf.o: $(SYSMONITOR) $(VMLINUX_H)
	@echo "Compiling eBPF bytecode: $(GREEN)$@$(NC) ..."
	$(Q)$(CL) $(KF) -DMONITOR_CONTAINER -Xclang -disable-llvm-passes -c $< -o - | opt -O2 -mtriple=bpf-pc-linux | llvm-dis | llc -march=bpf -mcpu=probe -filetype=obj -o $@

system_monitor.host.bpf.o: $(SYSMONITOR) $(VMLINUX_H)
	@echo "Compiling eBPF bytecode: $(GREEN)$@$(NC) ..."
	$(Q)$(CL) $(KF) -DMONITOR_HOST -Xclang -disable-llvm-passes -c $< -o - | opt -O2 -mtriple=bpf-pc-linux | llvm-dis | llc -march=bpf -mcpu=probe -filetype=obj -o $@

.PHONY: clean
clean:
	$(Q)rm -rf *.o $(VMLINUX)/vmlinux.h

.PHONY: clean-all
clean-all: clean
	$(Q)make clean -C $(LIBBPF)/src
