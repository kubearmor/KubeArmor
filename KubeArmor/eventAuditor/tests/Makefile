# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor


ifeq ($(V), 1)
	Q =	
else
	Q = @
endif

.PHONY: all
all: tests

# tests
BPFDIR     = $(realpath ../../BPF)
INCDIR     = $(BPFDIR)/include
LIBBPFOBJ  = $(INCDIR)/libbpf.a
CGOLDFLAGS = $(LIBBPFOBJ)
CGOCFLAGS  = $(INCDIR)

TESTSDIR   = $(realpath ../tests)
TESTS_GO   = $(wildcard $(TESTSDIR)/*.go)
TESTS      = $(TESTS_GO:.go=)


.PHONY: tests
tests: $(TESTS)

$(LIBBPFOBJ):
	$(Q)make -C $(BPFDIR)/../

$(TESTS): % : %.go |  $(LIBBPFOBJ)
	$(info INFO: compiling test $@)
	$(Q)CGO_LDFLAGS=$(CGOLDFLAGS) CGO_CFLAGS="-I $(CGOCFLAGS)" \
		go build -o $@ $^


# run tests

.PHONY: run-tests
run-tests: $(TESTS)
	$(Q)for test in $^; do \
		echo -e "\nINFO: running test $${test}"; \
		cd $(TESTSDIR); sudo $${test}; \
	done


# cleanup

clean:
	$(Q)rm -rf $(TESTS)
