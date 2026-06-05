#include "sentinel_vmi.h"
#include <stdint.h>
#include <stdio.h>

extern uint32_t heki_active_nonce;
extern uint32_t identify_malicious_pid(struct vmi_session *s);

// Temporary Authorized list
static uint64_t authorized_cr3 = 0;
static uint32_t authorized_pid = 0;

void npf_handler_cpuid_intercept(struct vmi_session *s, uint32_t eax,
                                 uint32_t ecx, uint64_t cr3) {
  if (eax == 0x48454B49) { // "HEKI" Magic
    if (ecx == heki_active_nonce && heki_active_nonce != 0) {
      printf("[HEKI-Drawbridge] CPUID intent registered for CR3: 0x%lx\n", cr3);
      authorized_cr3 = cr3;
      authorized_pid =
          identify_malicious_pid(s); // It's not malicious, it's telos_core
    } else {
      printf("[HEKI-Drawbridge] WARNING: CPUID intent rejected (invalid nonce: "
             "%x)\n",
             ecx);
    }
  }
}

int npf_handler_is_authorized(uint64_t cr3, uint32_t pid) {
  return (cr3 != 0 && authorized_cr3 == cr3) ||
         (pid != 0 && authorized_pid == pid);
}

void npf_handler_clear_authorized(void) {
  authorized_cr3 = 0;
  authorized_pid = 0;
}
