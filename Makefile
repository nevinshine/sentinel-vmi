CC = gcc
CFLAGS = -Wall -Wextra -O2 -g \
         -I./include \
         -I/usr/include/bpf

LDFLAGS = -lbpf -lelf

SRCS = src/main.c \
       src/kvmi_setup.c \
       src/memory.c \
       src/task_walker.c \
       src/npt_guard.c \
       src/npf_handler.c \
       src/bridge.c

OBJS = $(SRCS:.c=.o)
TARGET = sentinel-vmi

.PHONY: all clean test-unit

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test-unit:
	$(CC) $(CFLAGS) tests/test_memory.c \
	  src/memory.c -o test_memory $(LDFLAGS)
	$(CC) $(CFLAGS) tests/test_task_walker.c \
	  src/task_walker.c -o test_task_walker $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET) test_memory test_task_walker
