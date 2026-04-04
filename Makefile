CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -g \
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
       src/bridge.c

OBJS = $(SRCS:.c=.o)
TARGET = sentinel-vmi

TEST_SRCS = tests/test_memory.c \
            tests/test_task_walker.c \
            tests/test_npt.c \
            tests/test_bridge.c

.PHONY: all clean test-unit test

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

test_task_walker: tests/test_task_walker.c src/task_walker.c src/memory.c src/kvmi_setup.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_npt: tests/test_npt.c src/npt_guard.c src/npf_handler.c src/memory.c src/kvmi_setup.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_bridge: tests/test_bridge.c src/bridge.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test: test-unit

clean:
	rm -f $(OBJS) $(TARGET) test_memory test_task_walker test_npt test_bridge
