CC = gcc
CFLAGS = -Wall -Wextra -Werror -O3 -g -mavx2 -mfma \
         -I./include \
         -D_GNU_SOURCE

# libbpf/libelf are optional — only needed for bridge (Phase 4)
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
       src/bridge.c \
       src/heki_server.c \
       src/cpuid_handler.c \
       src/snapshot.c \
       src/symbols.c \
       src/provenance.c \
       src/integrity.c \
       src/differential.c \
       src/actor.c \
       src/ept/ept_mediation.c \
       src/regions.c \
       src/regulatory_daemon.c \
       src/equilibrium.c \
       src/stabilization.c \
       src/replay/capture_engine.c

OBJS = $(SRCS:.c=.o)
TARGET = sentinel-vmi

TEST_SRCS = tests/test_memory.c \
            tests/test_task_walker.c \
            tests/test_npt.c \
            tests/test_bridge.c \
            tests/test_snapshot.c

.PHONY: all clean test-unit test-snapshot test-live test

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

test-snapshot: test_snapshot_bin
	./test_snapshot_bin

test-live:
	@echo "Run inside nested KVM VM only"

test_memory: tests/test_memory.c src/memory.c src/kvmi_setup.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_task_walker: tests/test_task_walker.c src/task_walker.c src/memory.c src/kvmi_setup.c src/bridge.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_npt: tests/test_npt.c src/npt_guard.c src/npf_handler.c src/memory.c src/kvmi_setup.c src/bridge.c src/cpuid_handler.c src/heki_server.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_bridge: tests/test_bridge.c src/bridge.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_snapshot_bin: tests/test_snapshot.c src/snapshot.c src/memory.c src/task_walker.c src/bridge.c src/kvmi_setup.c src/symbols.c src/provenance.c src/integrity.c src/differential.c src/regions.c src/actor.c src/ept/ept_mediation.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test: test-unit test-snapshot

clean:
	rm -f $(OBJS) $(TARGET)
	rm -f tests/*.o test_memory test_task_walker test_npt test_bridge test_snapshot_bin test_collapse_bin bench/certainty_per_megacycle/*.o
