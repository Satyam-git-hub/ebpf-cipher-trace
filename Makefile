TARGET := ebpf-ciphertrace
BPF_OBJ := bpf_ciphertrace.o
BPF_SRC := bpf/ciphertrace.c
GO_SRC := cmd/agent/main.go

.PHONY: all clean build-bpf build-go generate

all: build-bpf build-go

build-bpf:
	go generate ./pkg/ebpf

build-go:
	go build -o $(TARGET) $(GO_SRC)

clean:
	rm -f $(TARGET) $(BPF_OBJ)
