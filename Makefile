CC = gcc

# ── Hardening flags (production-safe defaults) ────────────────────────────────
# -fstack-protector-strong   : SSP for functions with non-trivial stack frames
# -D_FORTIFY_SOURCE=3        : glibc buffer-overflow detection at runtime
#                              (requires glibc ≥ 2.35 and -O1 or higher).
#                              If your toolchain is older, override at the
#                              command line: make FORTIFY_LEVEL=2
# -fPIE / -pie               : position-independent executable (ASLR support)
# -Wl,-z,relro,-z,now        : full RELRO — resolve all symbols at load time
# -Wformat / -Werror=format-security : reject dangerous printf/scanf patterns
FORTIFY_LEVEL ?= 3

HARDENING_FLAGS = \
    -fstack-protector-strong \
    -D_FORTIFY_SOURCE=$(FORTIFY_LEVEL) \
    -fPIE \
    -Wformat \
    -Werror=format-security

HARDENING_LDFLAGS = \
    -pie \
    -Wl,-z,relro,-z,now

CFLAGS = -Wall -Wextra -Werror -O2 -g \
         -I./include \
         -D_GNU_SOURCE \
         $(HARDENING_FLAGS)

LDFLAGS = $(HARDENING_LDFLAGS)

# ── Debug / sanitizer build ───────────────────────────────────────────────────
# Enable with: make SANITIZE=1
# Disables -D_FORTIFY_SOURCE to avoid conflicts with ASan.
ifdef SANITIZE
CFLAGS  := $(filter-out -D_FORTIFY_SOURCE=$(FORTIFY_LEVEL),$(CFLAGS))
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

# ── Optional libbpf/libelf (Phase 4 bridge) ───────────────────────────────────
# Enable with: make USE_BPF=1
ifdef USE_BPF
CFLAGS  += -DHAVE_LIBBPF
LDFLAGS += -lbpf -lelf
endif

SRCS = src/main.c \
       src/kvmi_setup.c \
       src/memory.c \
       src/task_walker.c \
       src/npt_guard.c \
       src/npf_handler.c \
       src/bridge.c

OBJS = $(SRCS:.c=.o)
TARGET = sentinel-vmi

TEST_SRCS = tests/test_memory.c \
            tests/test_task_walker.c \
            tests/test_npt.c \
            tests/test_bridge.c

.PHONY: all clean test-unit test sanitize hardening-check

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test-unit: test_memory test_task_walker test_npt test_bridge
	./test_memory
	./test_task_walker
	./test_npt
	./test_bridge

test_memory: tests/test_memory.c src/memory.c src/kvmi_setup.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_task_walker: tests/test_task_walker.c src/task_walker.c src/memory.c src/kvmi_setup.c src/bridge.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_npt: tests/test_npt.c src/npt_guard.c src/npf_handler.c src/memory.c src/kvmi_setup.c src/bridge.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_bridge: tests/test_bridge.c src/bridge.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test: test-unit

# ── Convenience aliases ───────────────────────────────────────────────────────
# Build with ASan + UBSan enabled (does not alter the default 'all' target)
sanitize:
	$(MAKE) SANITIZE=1 all

# Verify hardening flags are present in the final binary
hardening-check:
	@echo "Checking hardening flags in $(TARGET)..."
	@objdump -d $(TARGET) 2>/dev/null | grep -q __stack_chk_fail && \
	    echo "  ✓ Stack protector active" || echo "  ✗ Stack protector NOT found"
	@readelf -l $(TARGET) 2>/dev/null | grep -q "GNU_RELRO" && \
	    echo "  ✓ RELRO segment present" || echo "  ✗ RELRO NOT found"
	@readelf -d $(TARGET) 2>/dev/null | grep -q "BIND_NOW" && \
	    echo "  ✓ BIND_NOW (full RELRO) active" || echo "  ✗ BIND_NOW NOT found"
	@readelf -h $(TARGET) 2>/dev/null | grep -q "DYN (Position" && \
	    echo "  ✓ PIE enabled" || echo "  ✗ PIE NOT detected"

clean:
	rm -f $(OBJS) $(TARGET) test_memory test_task_walker test_npt test_bridge
