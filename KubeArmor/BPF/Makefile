include Makefile.vars

.PHONY: all
all: chkdir syscall_test system_monitor.bpf.o system_monitor.container.bpf.o system_monitor.host.bpf.o

.PHONY: chkdir
chkdir:
ifeq (,$(wildcard $(KRNDIR)/Kconfig))
	@echo "Your kernel path[$(RED)$(KRNDIR)$(NC)] is incorrect. Use 'make KRNDIR=[KERNEL-SRC-PATH]'."
	Quitting 
else
	@echo "Using kernel path[$(GREEN)$(KRNDIR)$(NC)]"
endif
ifeq (,$(wildcard $(LIBBPF)/src/libbpf.c))
	git submodule update --init --recursive
endif
ifeq (,$(wildcard $(LIBBPF)/src/libbpf.a))
	make -C $(LIBBPF)/src
endif

.PHONY: syscall_test
syscall_test: tests/Makefile
	@make -C tests KRNDIR="$(KRNDIR)"

system_monitor.bpf.o: $(SYSMONITOR) syscall_test
	@echo "Compiling eBPF bytecode: $(GREEN)$@$(NC) ..."
	@echo "Using Compiler flags: $(CFlags)"
	$(Q)$(CL) $(KF) -DMONITOR_HOST_AND_CONTAINER $(CFlags) -c $< -o -| llc -march=bpf -mcpu=probe -filetype=obj -o $@

system_monitor.container.bpf.o: $(SYSMONITOR) syscall_test
	@echo "Compiling eBPF bytecode: $(GREEN)$@$(NC) ..."
	@echo "Using Compiler flags: $(CFlags)"
	$(Q)$(CL) $(KF) -DMONITOR_CONTAINER $(CFlags) -c $< -o -| llc -march=bpf -mcpu=probe -filetype=obj -o $@

system_monitor.host.bpf.o: $(SYSMONITOR) syscall_test
	@echo "Compiling eBPF bytecode: $(GREEN)$@$(NC) ..."
	@echo "Using Compiler flags: $(CFlags)"
	$(Q)$(CL) $(KF) -DMONITOR_HOST $(CFlags) -c $< -o -| llc -march=bpf -mcpu=probe -filetype=obj -o $@

# clean up
clean:
	@make -C tests clean
	$(Q)rm -rf *.o
