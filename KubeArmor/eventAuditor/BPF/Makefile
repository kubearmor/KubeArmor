ifeq ($(V), 1)
	Q =	
else
	Q = @
endif

OUTPUTDIR = ./output

.PHONY: all
all: libbpf vmlinuxh bpfobj


# libbpf

CC     = gcc
CFLAGS = -g -O2 -Werror -Wall -fpie

GIT            = $(shell which git)
LIBBPFDIR      = $(abspath ./libbpf)
LIBBPFOBJ      = $(OUTPUTDIR)/libbpf.a
LIBBPFSRCDIR   = $(LIBBPFDIR)/src
LIBBPFSRCFILES = $(wildcard $(LIBBPFSRCDIR)/*.[ch])
LIBBPFDESTDIR  = $(abspath $(OUTPUTDIR))
LIBBPFOBJDIR   = $(LIBBPFDESTDIR)/libbpf

.PHONY: libbpf
libbpf: $(LIBBPFOBJ)

$(LIBBPFOBJ): $(LIBBPFSRCDIR) $(LIBBPFSRCFILES) | $(OUTPUTDIR)
	$(info INFO: compiling $@)
	$(Q)CC="$(CC)" CFLAGS="$(CFLAGS)" \
	$(MAKE) -C $(LIBBPFSRCDIR) \
		BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPFOBJDIR) \
		DESTDIR=$(LIBBPFDESTDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= \
		install


$(LIBBPFSRCDIR):
ifeq ($(wildcard $@), )
	$(info INFO: updating submodule 'libbpf')
	$(Q)$(GIT) submodule update --init --recursive
endif


# vmlinux header file

BPFTOOL  = $(shell which bpftool)
BTFFILE  = /sys/kernel/btf/vmlinux
VMLINUXH = $(OUTPUTDIR)/vmlinux.h

.PHONY: vmlinuxh
vmlinuxh: $(VMLINUXH)

$(VMLINUXH): $(BTFFILE) | $(OUTPUTDIR)
	$(info INFO: generating $@ from $<)
	$(Q)$(BPFTOOL) btf dump file $< format c > $@;

$(BTFFILE):
ifeq ($(wildcard $@), )
	$(error ERROR: kernel does not seem to support BTF)
endif


# bpf objects

CLANG      = clang
CLANGFLAGS = -g -O2 -c -target bpf
CLANGINC   = $(OUTPUTDIR)
BPFOBJDIR  = $(OUTPUTDIR)
BPFS_C     = $(wildcard *.bpf.c)
BPFS_O     = $(addprefix $(BPFOBJDIR)/, $(BPFS_C:.c=.o))

.PHONY: bpfobj
bpfobj: libbpf vmlinuxh $(BPFS_O)

$(BPFOBJDIR)/%.o: %.c | $(BPFOBJDIR)
	$(info INFO: compiling bpf object $@)
	$(Q)$(CLANG) $(CLANGFLAGS) -I $(CLANGINC) -o $@ $<


# output

$(OUTPUTDIR):
	$(Q)mkdir -p $@


# cleanup

clean:
	$(Q)rm -rf $(OUTPUTDIR)
