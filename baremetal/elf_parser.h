#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "policy.h"

#define EI_NIDENT 16

/* ELF64 Types */
typedef uint64_t Elf64_Addr;
typedef uint16_t Elf64_Half;
typedef uint64_t Elf64_Off;
typedef int32_t  Elf64_Sword;
typedef int64_t  Elf64_Sxword;
typedef uint32_t Elf64_Word;
typedef uint64_t Elf64_Xword;

/* ELF Header */
typedef struct {
    unsigned char e_ident[EI_NIDENT];
    Elf64_Half    e_type;
    Elf64_Half    e_machine;
    Elf64_Word    e_version;
    Elf64_Addr    e_entry;
    Elf64_Off     e_phoff;
    Elf64_Off     e_shoff;
    Elf64_Word    e_flags;
    Elf64_Half    e_ehsize;
    Elf64_Half    e_phentsize;
    Elf64_Half    e_phnum;
    Elf64_Half    e_shentsize;
    Elf64_Half    e_shnum;
    Elf64_Half    e_shstrndx;
} Elf64_Ehdr;

/* Section Header */
typedef struct {
    Elf64_Word    sh_name;
    Elf64_Word    sh_type;
    Elf64_Xword   sh_flags;
    Elf64_Addr    sh_addr;
    Elf64_Off     sh_offset;
    Elf64_Xword   sh_size;
    Elf64_Word    sh_link;
    Elf64_Word    sh_info;
    Elf64_Xword   sh_addralign;
    Elf64_Xword   sh_entsize;
} Elf64_Shdr;

/* Expected constants */
#define EM_RISCV  243

/**
 * Validates the ELF64 Header and boundaries.
 * Returns true if valid.
 */
bool elf64_is_valid(const uint8_t *blob, size_t size);

/**
 * Extracts the e_entry point from the ELF header.
 * Returns true if valid and sets *out_entry.
 */
bool elf64_get_entry(const uint8_t *blob, size_t size, uint64_t *out_entry);

/**
 * Searches the ELF headers for a specific section by name.
 * Returns true if found, sets *out_offset and *out_size.
 */
bool elf64_find_section(const uint8_t *blob, size_t size, const char *section_name, uint64_t *out_offset, uint64_t *out_size);

/**
 * Extracts a TelosPolicyEntry from the `.telos_policy` section of the binary.
 * Returns true if the policy was found and successfully extracted.
 */
bool telos_policy_extract(const uint8_t *blob, size_t size, TelosPolicyEntry *out_policy);

#endif // ELF_PARSER_H
