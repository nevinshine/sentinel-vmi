#include "sentinel_vmi.h"
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// ──────────────────────────────────────────────
// Utility: Simple JSON string extraction
// ──────────────────────────────────────────────
static void extract_json_string(const char *json, const char *key, char *out,
                                size_t out_sz) {
  out[0] = '\0';
  char search[128];
  snprintf(search, sizeof(search), "\"%s\"", key);

  const char *pos = strstr(json, search);
  if (!pos)
    return;

  pos += strlen(search);
  while (*pos && (*pos == ' ' || *pos == ':' || *pos == '\t'))
    pos++;

  if (*pos == '"') {
    pos++;
    size_t i = 0;
    while (*pos && *pos != '"' && i < out_sz - 1) {
      out[i++] = *pos++;
    }
    out[i] = '\0';
  }
}

static uint64_t extract_json_hex(const char *json, const char *key) {
  char buf[64];
  extract_json_string(json, key, buf, sizeof(buf));
  if (buf[0] == '\0')
    return 0;
  return strtoull(buf, NULL, 16);
}

static uint32_t extract_json_int(const char *json, const char *key) {
  char search[128];
  snprintf(search, sizeof(search), "\"%s\"", key);

  const char *pos = strstr(json, search);
  if (!pos)
    return 0;

  pos += strlen(search);
  while (*pos && (*pos == ' ' || *pos == ':' || *pos == '\t'))
    pos++;

  return (uint32_t)strtoul(pos, NULL, 10);
}

// ──────────────────────────────────────────────
// Checksum Verification
// ──────────────────────────────────────────────
static int verify_sha256(const char *bin_path, const char *expected_hash) {
  if (!expected_hash || expected_hash[0] == '\0')
    return -1;

  char cmd[512];
  snprintf(cmd, sizeof(cmd), "sha256sum \"%s\" 2>/dev/null", bin_path);

  FILE *fp = popen(cmd, "r");
  if (!fp)
    return -1;

  char output[256] = {0};
  if (!fgets(output, sizeof(output), fp)) {
    pclose(fp);
    return -1;
  }
  pclose(fp);

  char actual_hash[128] = {0};
  sscanf(output, "%127s", actual_hash);

  if (strcmp(actual_hash, expected_hash) != 0) {
    fprintf(stderr,
            "[Snapshot] Checksum mismatch!\n"
            "  Expected: %s\n"
            "  Actual:   %s\n",
            expected_hash, actual_hash);
    return -1;
  }

  return 0;
}

// ──────────────────────────────────────────────
// Structural Validation
// ──────────────────────────────────────────────
int validate_snapshot_metadata(const struct snapshot_metadata *meta,
                               uint64_t file_size) {
  if (!meta)
    return -1;

  int valid = 1;

  // 1. Paging Mode
  if (strcmp(meta->paging_mode, "x86_64_4level") != 0) {
    fprintf(stderr, "[Snapshot] Invalid/unsupported paging mode: '%s'\n",
            meta->paging_mode);
    valid = 0;
  }

  // 2. CR3 Alignment
  // PCID uses the lower 12 bits, so we don't strictly enforce 4KB alignment here.
  if (meta->vcpu_cr3 == 0) {
    fprintf(stderr, "[Snapshot] Invalid CR3: 0x%lx\n", meta->vcpu_cr3);
    valid = 0;
  }

  // 3. RIP Canonicality (x86_64 canonical addresses)
  // Bits 48-63 must be copies of bit 47.
  uint64_t rip = meta->vcpu_rip;
  int bit47 = (rip >> 47) & 1;
  uint64_t high_bits = rip >> 48;
  if ((bit47 == 0 && high_bits != 0x0000) ||
      (bit47 == 1 && high_bits != 0xFFFF)) {
    fprintf(stderr, "[Snapshot] Non-canonical RIP: 0x%lx\n", rip);
    valid = 0;
  }

  // 4. Phys Base Alignment
  if ((meta->phys_base & 0xFFF) != 0) {
    fprintf(stderr, "[Snapshot] Phys base not page-aligned: 0x%lx\n",
            meta->phys_base);
    valid = 0;
  }

  // 5. KASLR Sane Bounds (rough estimate: kernel text is in high memory)
  if (meta->kaslr_slide > 0 && meta->kaslr_slide < 0xFFFFFFFF00000000ULL) {
    fprintf(stderr, "[Snapshot] KASLR slide seems invalid: 0x%lx\n",
            meta->kaslr_slide);
    valid = 0;
  }

  // 6. Minimum Size constraints
  if (file_size < VMI_PAGE_SIZE) {
    fprintf(stderr, "[Snapshot] Snapshot file size too small: %lu bytes\n",
            file_size);
    valid = 0;
  }

  return valid ? 0 : -1;
}

// ──────────────────────────────────────────────
// Core API
// ──────────────────────────────────────────────
struct vmi_session *vmi_session_from_snapshot(const char *bin_path,
                                              const char *json_path) {
  printf("[Snapshot] Loading snapshot from %s\n", bin_path);

  // 1. Read JSON file
  int fd_json = open(json_path, O_RDONLY);
  if (fd_json < 0) {
    perror("[Snapshot] Failed to open metadata");
    return NULL;
  }

  struct stat st_json;
  if (fstat(fd_json, &st_json) < 0) {
    close(fd_json);
    return NULL;
  }

  char *json_buf = malloc(st_json.st_size + 1);
  if (!json_buf) {
    close(fd_json);
    return NULL;
  }

  if (read(fd_json, json_buf, st_json.st_size) != st_json.st_size) {
    free(json_buf);
    close(fd_json);
    return NULL;
  }
  json_buf[st_json.st_size] = '\0';
  close(fd_json);

  // 2. Parse metadata
  struct snapshot_metadata meta;
  memset(&meta, 0, sizeof(meta));

  extract_json_string(json_buf, "kernel_release", meta.kernel_release,
                      sizeof(meta.kernel_release));
  extract_json_string(json_buf, "kernel_build_id", meta.kernel_build_id,
                      sizeof(meta.kernel_build_id));
  extract_json_string(json_buf, "capture_timestamp", meta.capture_timestamp,
                      sizeof(meta.capture_timestamp));
  extract_json_string(json_buf, "snapshot_sha256", meta.snapshot_sha256,
                      sizeof(meta.snapshot_sha256));
  extract_json_string(json_buf, "kallsyms_sha256", meta.kallsyms_sha256,
                      sizeof(meta.kallsyms_sha256));

  extract_json_string(json_buf, "mode", meta.paging_mode,
                      sizeof(meta.paging_mode));
  meta.page_shift = extract_json_int(json_buf, "page_shift");

  meta.kaslr_slide = extract_json_hex(json_buf, "kaslr_slide");
  meta.phys_base = extract_json_hex(json_buf, "phys_base");
  meta.vcpu_rip = extract_json_hex(json_buf, "rip");
  meta.vcpu_rsp = extract_json_hex(json_buf, "rsp");
  meta.vcpu_cr3 = extract_json_hex(json_buf, "cr3");

  free(json_buf);

  // 3. Open Binary and Check Size
  int fd_bin = open(bin_path, O_RDONLY);
  if (fd_bin < 0) {
    perror("[Snapshot] Failed to open snapshot binary");
    return NULL;
  }

  struct stat st_bin;
  if (fstat(fd_bin, &st_bin) < 0) {
    close(fd_bin);
    return NULL;
  }

  // 4. Validate Checksum & Structure
  if (verify_sha256(bin_path, meta.snapshot_sha256) < 0) {
    close(fd_bin);
    return NULL;
  }

  if (validate_snapshot_metadata(&meta, st_bin.st_size) < 0) {
    close(fd_bin);
    return NULL;
  }

  // 5. Mmap Binary into host memory
  void *mapped = mmap(NULL, st_bin.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd_bin, 0);
  close(fd_bin); // Safe to close after mmap
  if (mapped == MAP_FAILED) {
    perror("[Snapshot] Failed to mmap binary");
    return NULL;
  }

  // 6. Build the VMI Session
  struct vmi_session *s = calloc(1, sizeof(*s));
  if (!s) {
    munmap(mapped, st_bin.st_size);
    return NULL;
  }

  s->memslots = calloc(1, sizeof(struct vmi_memslot));
  if (!s->memslots) {
    free(s);
    munmap(mapped, st_bin.st_size);
    return NULL;
  }

  s->nr_memslots = 1;
  s->memslots[0].guest_phys_addr = meta.phys_base;
  s->memslots[0].memory_size = st_bin.st_size;
  s->memslots[0].userspace_addr = mapped;
  s->memslots[0].flags = 0; // NOT VMI_MEMSLOT_F_REMOTE_PROCESS

  // KPTI uses CR3 | 0x1000 for the user page directory.
  // PCID uses the lower 12 bits.
  // We mask out the lower 13 bits (0x1FFF) to get the physical base of the kernel page directory.
  s->kernel_pgd = meta.vcpu_cr3 & ~0x1FFFULL;
  s->kaslr_offset = meta.kaslr_slide;
  // Phase 16: VM-Wide Semantic Field Thermodynamics
  s->field.legitimacy.structural = 1.0f;
  s->field.legitimacy.behavioral = 1.0f;
  s->field.legitimacy.continuity = 1.0f;
  s->field.legitimacy.provenance = 1.0f;
  
  s->field.inertia.topology_resistance = 1.0f;
  s->field.inertia.authority_resistance = 1.0f;
  s->field.inertia.namespace_resistance = 1.0f;
  s->field.semantic_temperature = 0.0f;
  s->field.capability_pressure = 0.0f;
  s->field.authority_entropy = 0.0f;
  s->field.authority_centralization = 1.0f;
  s->field.collapse_hysteresis = 0.0f;
  s->field.authority_gradient = 0.0f;
  s->field.legitimacy_flux = 0.0f;
  s->field.authority_curvature = 0.0f;
  s->field.closure_state = FIELD_COHERENT;
  s->field.hysteresis_epochs = 0;
  s->field.recovery_gradient = 0.0f;
  
  memset(&s->field.conservation, 0, sizeof(s->field.conservation));
  memset(&s->field.pressure, 0, sizeof(s->field.pressure));
  memset(&s->field.trajectory, 0, sizeof(s->field.trajectory));
  memset(&s->field.boundaries, 0, sizeof(s->field.boundaries));
  memset(&s->field.constraints, 0, sizeof(s->field.constraints));
  memset(&s->field.basin, 0, sizeof(s->field.basin));
  memset(&s->field.observer, 0, sizeof(s->field.observer));
  memset(&s->field.stab_gradient, 0, sizeof(s->field.stab_gradient));
  memset(&s->field.shear, 0, sizeof(s->field.shear));
  
  s->field.anticipated_collapse = COLLAPSE_NONE;
  s->field.basin.attractor = ATTRACTOR_HEALTHY;
  
  s->field.current_epoch = 1;
  s->field.coherence_epoch = 1;
  s->semantic_epoch = 1;

  printf("[Snapshot] Success! Kernel %s (build: %s)\n", meta.kernel_release,
         meta.kernel_build_id);
  printf("[Snapshot] CR3: 0x%lx, RIP: 0x%lx\n", meta.vcpu_cr3, meta.vcpu_rip);

  return s;
}
