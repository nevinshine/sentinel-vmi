// src/npf_handler.c
#include "sentinel_vmi.h"
#include <stdio.h>

int npf_handler_init(struct vmi_session *s) {
    (void)s;
    return 0;
}

void npf_handler_process(struct vmi_session *s, uint64_t gpa, int write_access) {
    (void)s;
    (void)gpa;
    (void)write_access;
    printf("[NPF-Handler] Handling Nested Page Fault at %lx (write=%d)\n", gpa, write_access);
}
