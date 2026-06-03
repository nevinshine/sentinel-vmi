#!/usr/bin/env python3
"""
TCA Root of Trust — Guest Binary Signing Utility

Generates an Ed25519 keypair (or loads an existing one) and signs the .text
section of a RISC-V ELF guest binary. The 64-byte signature is written to
a raw binary file that gets embedded into the guest ELF via .incbin.

Usage:
    python3 sign_guest.py --keygen                     # Generate keypair
    python3 sign_guest.py --sign guest_payload.elf     # Sign .text section
"""

import argparse
import struct
import sys
import os

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("ERROR: 'cryptography' package required. Install with: pip install cryptography")
    sys.exit(1)

KEY_DIR = os.path.dirname(os.path.abspath(__file__))
PRIV_KEY_PATH = os.path.join(KEY_DIR, "rot_priv.pem")
PUB_KEY_PATH  = os.path.join(KEY_DIR, "rot_pub.key")   # Raw 32-byte public key
SIG_PATH      = os.path.join(KEY_DIR, "guest_sig.bin")  # Raw 64-byte signature

# --- ELF64 Parsing (minimal) ---

ELF_MAGIC = b'\x7fELF'
EI_CLASS_64 = 2
EM_RISCV = 243

def parse_elf_sections(data):
    """Parse ELF64 section headers and return a dict of name -> (offset, size)."""
    if data[:4] != ELF_MAGIC or data[4] != EI_CLASS_64:
        raise ValueError("Not a valid ELF64 binary")

    # ELF64 header fields
    e_shoff    = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum    = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]

    if e_shoff == 0 or e_shnum == 0:
        raise ValueError("No section headers found")

    # Read string table section header
    strtab_hdr_off = e_shoff + e_shstrndx * e_shentsize
    strtab_offset = struct.unpack_from('<Q', data, strtab_hdr_off + 0x18)[0]
    strtab_size   = struct.unpack_from('<Q', data, strtab_hdr_off + 0x20)[0]
    strtab = data[strtab_offset:strtab_offset + strtab_size]

    sections = {}
    for i in range(e_shnum):
        shdr_off = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack_from('<I', data, shdr_off)[0]
        sh_offset   = struct.unpack_from('<Q', data, shdr_off + 0x18)[0]
        sh_size     = struct.unpack_from('<Q', data, shdr_off + 0x20)[0]

        # Extract null-terminated name from string table
        name_end = strtab.index(b'\x00', sh_name_idx)
        name = strtab[sh_name_idx:name_end].decode('ascii', errors='replace')
        if name:
            sections[name] = (sh_offset, sh_size)

    return sections


def cmd_keygen():
    """Generate a new Ed25519 keypair for the Root of Trust."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Save private key as PEM
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(PRIV_KEY_PATH, 'wb') as f:
        f.write(pem)

    # Save raw 32-byte public key (for .incbin in boot.S)
    raw_pub = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    with open(PUB_KEY_PATH, 'wb') as f:
        f.write(raw_pub)

    print(f"[KEYGEN] Root of Trust keypair generated.")
    print(f"  Private key: {PRIV_KEY_PATH}")
    print(f"  Public key:  {PUB_KEY_PATH} ({len(raw_pub)} bytes)")
    print(f"  Public key hex: {raw_pub.hex()}")


def cmd_sign(elf_path):
    """Sign the .text section of the guest ELF binary."""
    # Load private key
    if not os.path.exists(PRIV_KEY_PATH):
        print("ERROR: No private key found. Run with --keygen first.")
        sys.exit(1)

    with open(PRIV_KEY_PATH, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Load ELF
    with open(elf_path, 'rb') as f:
        elf_data = f.read()

    sections = parse_elf_sections(elf_data)

    if '.text' not in sections:
        print("ERROR: No .text section found in ELF binary.")
        sys.exit(1)

    text_offset, text_size = sections['.text']
    text_data = elf_data[text_offset:text_offset + text_size]

    print(f"[SIGN] Hashing .text section ({text_size} bytes at offset 0x{text_offset:x})...")

    # Sign the raw .text bytes with Ed25519
    signature = private_key.sign(text_data)

    # Write raw 64-byte signature
    with open(SIG_PATH, 'wb') as f:
        f.write(signature)

    print(f"[SIGN] Signature written to {SIG_PATH} ({len(signature)} bytes)")
    print(f"  Signature hex: {signature[:16].hex()}...{signature[-16:].hex()}")


def main():
    parser = argparse.ArgumentParser(description="TCA Root of Trust Signing Utility")
    parser.add_argument('--keygen', action='store_true', help='Generate Root of Trust keypair')
    parser.add_argument('--sign', type=str, metavar='ELF', help='Sign guest ELF .text section')
    args = parser.parse_args()

    if args.keygen:
        cmd_keygen()
    elif args.sign:
        cmd_sign(args.sign)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
