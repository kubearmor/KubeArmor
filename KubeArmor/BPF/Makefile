include Makefile.vars

.PHONY: all
all: kernel_headers libbpf syscall_test system_monitor.bpf.o system_monitor.container.bpf.o system_monitor.host.bpf.o

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

.PHONY: syscall_test
syscall_test: tests/Makefile
	$(Q)make -C tests KRNDIR="$(KRNDIR)"

system_monitor.bpf.o: $(SYSMONITOR) $(VMLINUX_H) syscall_test
	@echo "Compiling eBPF bytecode: $(GREEN)$@$(NC) ..."
	@echo "Using Compiler flags: $(CFlags)"
	$(Q)$(CL) $(KF) -DMONITOR_HOST_AND_CONTAINER $(CFlags) -c $< -o -| llc -march=bpf -mcpu=probe -filetype=obj -o $@

system_monitor.container.bpf.o: $(SYSMONITOR) $(VMLINUX_H) syscall_test
	@echo "Compiling eBPF bytecode: $(GREEN)$@$(NC) ..."
	@echo "Using Compiler flags: $(CFlags)"
	$(Q)$(CL) $(KF) -DMONITOR_CONTAINER $(CFlags) -c $< -o -| llc -march=bpf -mcpu=probe -filetype=obj -o $@

system_monitor.host.bpf.o: $(SYSMONITOR) $(VMLINUX_H) syscall_test
	@echo "Compiling eBPF bytecode: $(GREEN)$@$(NC) ..."
	@echo "Using Compiler flags: $(CFlags)"
	$(Q)$(CL) $(KF) -DMONITOR_HOST $(CFlags) -c $< -o -| llc -march=bpf -mcpu=probe -filetype=obj -o $@

.PHONY: clean
clean:
	@make -C tests clean
	$(Q)rm -rf *.o $(VMLINUX)/vmlinux.h

.PHONY: clean-all
clean-all: clean
	$(Q)make clean -C $(LIBBPF)/src
