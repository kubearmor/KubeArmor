ARCH=$(shell uname -m)

TARGET := entrypoint
TARGET_BPF := $(TARGET).bpf.o

BPF_DIR := ./BPF

GO_SRC := *.go
BPF_SRC := $(wildcard $(BPF_DIR)/*.bpf.c)

#LIBBPF_HEADERS := /usr/include/bpf
LIBBPF_HEADERS := /home/knownymous/go/src/github.com/libbpf/include/bpf
#LIBBPF_OBJ := /home/knownymous/go/src/github.com/libbpf/include/libbpf.a
LIBBPF_OBJ := /home/knownymous/linux/tools/bpf/resolve_btfids/libbpf/libbpf.a
#LIBBPF_OBJ := /usr/lib/$(ARCH)-linux-gnu/libbpf.a

.PHONY: all
all: $(TARGET) $(TARGET_BPF)

go_env := CC=clang CGO_CFLAGS="-I $(LIBBPF_HEADERS)" CGO_LDFLAGS="$(LIBBPF_OBJ)"
$(TARGET): $(GO_SRC)
	$(go_env) go build -o $(TARGET) 

$(TARGET_BPF): $(BPF_SRC)
	clang \
		-I /usr/include/$(ARCH)-linux-gnu \
		-O2 -c -target bpf \
		-o $@ $<

.PHONY: clean
clean:
	go clean

