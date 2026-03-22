// src/memory.c
#include "sentinel_vmi.h"
#include <stdio.h>

int vmi_read_physical(struct vmi_session *s, uint64_t gpa, void *buf, size_t size) {
    (void)s;
    (void)gpa;
    (void)buf;
    (void)size;
    return 0;
}

int vmi_gva_to_gpa(struct vmi_session *s, uint64_t gva, uint64_t *gpa) {
    (void)s;
    (void)gva;
    if (gpa) *gpa = 0;
    return 0;
}
