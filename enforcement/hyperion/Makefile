CLANG ?= clang
GO ?= go
BIN_DIR := bin

export BPF_CLANG := $(CLANG)
export BPF_CFLAGS_BASE := -O2 -g -Wall -Werror -Wno-missing-declarations -I/usr/include/x86_64-linux-gnu

.PHONY: all clean build build-release build-instrumented test-ttl test-saturation

all: build-release

build-release: export BPF_CFLAGS := $(BPF_CFLAGS_BASE)
build-release: generate compile

build-instrumented: export BPF_CFLAGS := $(BPF_CFLAGS_BASE) -DINSTRUMENTATION_ENABLED
build-instrumented: generate compile

generate:
	@echo "  [BPF] Generating Artifacts..."
	cd internal/xdp && env -u GOARCH $(GO) generate

compile:
	@mkdir -p $(BIN_DIR)
	@echo "  [GO] Compiling Hyperiond..."
	$(GO) build -o $(BIN_DIR)/hyperiond ./cmd/hyperiond
	@echo "  [GO] Compiling Flowctl..."
	$(GO) build -o $(BIN_DIR)/flowctl ./cmd/flowctl

test-ttl: build-release
	@echo "  [TEST] Running TTL Recovery Integration Test..."
	sudo ./tests/test_ttl_recovery.sh

test-saturation: build-instrumented
	@echo "  [TEST] Running Saturation & Latency Test..."
	sudo ./tests/test_saturation.sh

clean:
	rm -rf $(BIN_DIR)
	rm -f internal/xdp/bpf_*.go internal/xdp/bpf_*.o
