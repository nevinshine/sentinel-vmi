CC=clang
CFLAGS=--target=riscv64 -march=rv64g -mabi=lp64 -mcmodel=medany -O2 -nostdlib -fno-builtin -fPIC

all: hypervisor.elf

guest_payload.elf: dummy_guest.S
	$(CC) $(CFLAGS) -c dummy_guest.S -o dummy_guest.o
	$(CC) $(CFLAGS) -fuse-ld=lld -Wl,-Ttext=0x80200000 dummy_guest.o -o guest_payload.elf

boot.o: boot.S guest_payload.elf
	$(CC) $(CFLAGS) -c boot.S -o boot.o

trap_entry.o: trap_entry.S
	$(CC) $(CFLAGS) -c trap_entry.S -o trap_entry.o

hypervisor.elf: boot.o trap_entry.o hypervisor.c elf_parser.c
	$(CC) $(CFLAGS) -fuse-ld=lld -Wl,-Ttext=0x80000000 boot.o trap_entry.o hypervisor.c elf_parser.c -o hypervisor.elf

clean:
	rm -f *.o *.elf
