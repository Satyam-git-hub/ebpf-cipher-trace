TARGET := ebpf-ciphertrace
BPF_OBJ := bpf_ciphertrace.o
BPF_SRC := bpf/ciphertrace.c
GO_SRC := cmd/agent/main.go

CLANG := $(abspath ./clang+llvm-14.0.0-x86_64-linux-gnu-ubuntu-18.04/bin/clang)
CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I$(abspath ./clang+llvm-14.0.0-x86_64-linux-gnu-ubuntu-18.04/include) -I$(abspath ./internal)

.PHONY: all clean build-bpf build-go

all: build-bpf build-go

build-bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(CFLAGS) -c $< -o $@

build-go:
	go build -o $(TARGET) $(GO_SRC)

clean:
	rm -f $(TARGET) $(BPF_OBJ)
