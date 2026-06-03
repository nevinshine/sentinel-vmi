CC=clang
CFLAGS=--target=riscv64 -march=rv64g -mabi=lp64 -mcmodel=medany -O2 -nostdlib -fno-builtin -fPIC
CRYPTO_CFLAGS=$(CFLAGS) -DED25519_NO_SEED

# Ed25519 crypto sources (vendored orlp/ed25519 ref10)
CRYPTO_SRCS=crypto/sha512.c crypto/verify.c crypto/ge.c crypto/fe.c crypto/sc.c \
            crypto/sign.c crypto/keypair.c

all: hypervisor.elf

guest_payload.elf: dummy_guest.S
	$(CC) $(CFLAGS) -c dummy_guest.S -o dummy_guest.o
	$(CC) $(CFLAGS) -fuse-ld=lld -Wl,-Ttext=0x80200000 dummy_guest.o -o guest_payload.elf

sign: guest_payload.elf
	python3 sign_guest.py --sign guest_payload.elf

boot.o: boot.S guest_payload.elf sign
	$(CC) $(CFLAGS) -c boot.S -o boot.o

trap_entry.o: trap_entry.S
	$(CC) $(CFLAGS) -c trap_entry.S -o trap_entry.o

hypervisor.elf: boot.o trap_entry.o hypervisor.c elf_parser.c libc_stubs.c $(CRYPTO_SRCS) hypervisor.ld
	$(CC) $(CRYPTO_CFLAGS) -fuse-ld=lld -T hypervisor.ld boot.o trap_entry.o hypervisor.c elf_parser.c libc_stubs.c $(CRYPTO_SRCS) -o hypervisor.elf

keygen:
	python3 sign_guest.py --keygen

clean:
	rm -f *.o *.elf guest_sig.bin
