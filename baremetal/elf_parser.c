#include "elf_parser.h"

/* Simple custom strcmp to avoid libc dependencies.
 * Also enforces a maximum length (max_len) to prevent out-of-bounds reads.
 */
static int safe_strcmp(const char *s1, const char *s2, size_t max_len) {
    for (size_t i = 0; i < max_len; i++) {
        if (s1[i] != s2[i]) {
            return s1[i] - s2[i];
        }
        if (s1[i] == '\0') {
            return 0;
        }
    }
    // If we reached max_len without a null terminator, they matched up to max_len.
    // However, if one string is supposed to be null terminated here and isn't, they don't truly match.
    // For our purposes (matching exact section names), if we hit max_len without '\0', 
    // it's safest to say they do NOT match if the target string (s2) expects a '\0' soon.
    // Since s2 is usually a constant like ".telos_policy", if s1 didn't hit '\0', it means s1 is longer.
    return 1; 
}

bool elf64_is_valid(const uint8_t *blob, size_t size) {
    if (!blob || size < sizeof(Elf64_Ehdr)) {
        return false;
    }

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)blob;

    // Check magic bytes: "\x7fELF"
    if (ehdr->e_ident[0] != 0x7f ||
        ehdr->e_ident[1] != 'E'  ||
        ehdr->e_ident[2] != 'L'  ||
        ehdr->e_ident[3] != 'F') {
        return false;
    }

    // Check class (64-bit)
    if (ehdr->e_ident[4] != 2) {
        return false;
    }

    // Check Architecture (RISC-V)
    if (ehdr->e_machine != EM_RISCV) {
        return false;
    }

    return true;
}

bool elf64_get_entry(const uint8_t *blob, size_t size, uint64_t *out_entry) {
    if (!elf64_is_valid(blob, size)) {
        return false;
    }
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)blob;
    if (out_entry) *out_entry = ehdr->e_entry;
    return true;
}

bool elf64_find_section(const uint8_t *blob, size_t size, const char *section_name, uint64_t *out_offset, uint64_t *out_size) {
    if (!elf64_is_valid(blob, size)) {
        return false;
    }

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)blob;

    // 1. Validate e_shoff (Section Header Offset) is within the binary boundaries.
    if (ehdr->e_shoff == 0 || ehdr->e_shoff + ((uint64_t)ehdr->e_shnum * ehdr->e_shentsize) > size) {
        return false;
    }

    // 2. Ensure e_shstrndx (String Table Index) is a valid index.
    if (ehdr->e_shstrndx >= ehdr->e_shnum) {
        return false;
    }

    // Calculate pointer to the section headers
    const uint8_t *shdrs = blob + ehdr->e_shoff;

    // Get the String Table Section Header
    const Elf64_Shdr *shstrtab_shdr = (const Elf64_Shdr *)(shdrs + (ehdr->e_shstrndx * ehdr->e_shentsize));

    // Validate string table offset and size
    if (shstrtab_shdr->sh_offset + shstrtab_shdr->sh_size > size) {
        return false;
    }

    const char *strtab = (const char *)(blob + shstrtab_shdr->sh_offset);
    uint64_t strtab_size = shstrtab_shdr->sh_size;

    // Find the length of our target section name
    size_t target_len = 0;
    while (section_name[target_len] != '\0') target_len++;

    // Iterate over all section headers
    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = (const Elf64_Shdr *)(shdrs + (i * ehdr->e_shentsize));

        // Ensure the string name offset is within the string table bounds
        if (shdr->sh_name >= strtab_size) {
            continue;
        }

        const char *name = strtab + shdr->sh_name;
        size_t max_cmp_len = strtab_size - shdr->sh_name;

        // 3. Enforce a maximum string length boundary to prevent reading off the end of memory
        if (safe_strcmp(name, section_name, max_cmp_len) == 0) {
            // Found it! Validate its data offset/size
            if (shdr->sh_offset + shdr->sh_size > size) {
                return false;
            }

            if (out_offset) *out_offset = shdr->sh_offset;
            if (out_size)   *out_size   = shdr->sh_size;
            return true;
        }
    }

    return false;
}

bool telos_policy_extract(const uint8_t *blob, size_t size, TelosPolicyEntry *out_policy) {
    uint64_t sec_offset;
    uint64_t sec_size;

    if (!elf64_find_section(blob, size, ".telos_policy", &sec_offset, &sec_size)) {
        return false;
    }

    if (sec_size < sizeof(TelosPolicyEntry)) {
        return false;
    }

    const TelosPolicyEntry *entry = (const TelosPolicyEntry *)(blob + sec_offset);

    if (out_policy) {
        uint8_t *dst = (uint8_t *)out_policy;
        const uint8_t *src = (const uint8_t *)entry;
        for (size_t i = 0; i < sizeof(TelosPolicyEntry); i++) {
            dst[i] = src[i];
        }
    }

    return true;
}

uint32_t telos_policy_extract_all(const uint8_t *blob, size_t size,
                                   TelosPolicyEntry *out_policies, uint32_t max_count) {
    uint64_t sec_offset;
    uint64_t sec_size;

    if (!elf64_find_section(blob, size, ".telos_policy", &sec_offset, &sec_size)) {
        return 0;
    }

    uint32_t entry_count = (uint32_t)(sec_size / sizeof(TelosPolicyEntry));
    if (entry_count > max_count) {
        entry_count = max_count;
    }
    if (entry_count == 0) {
        return 0;
    }

    for (uint32_t i = 0; i < entry_count; i++) {
        const uint8_t *src = blob + sec_offset + (i * sizeof(TelosPolicyEntry));
        uint8_t *dst = (uint8_t *)&out_policies[i];
        for (size_t b = 0; b < sizeof(TelosPolicyEntry); b++) {
            dst[b] = src[b];
        }
    }

    return entry_count;
}
