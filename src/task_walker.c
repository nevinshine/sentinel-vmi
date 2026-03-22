// src/task_walker.c
#include "sentinel_vmi.h"
#include <stdio.h>

void task_walker_dump(struct vmi_session *s) {
    (void)s;
    printf("[TaskWalker] Walking task_structs...\n");
}

int task_walker_find_pid(struct vmi_session *s, uint32_t pid, uint64_t *task_addr) {
    (void)s;
    (void)pid;
    if (task_addr) *task_addr = 0;
    return 0; // Fake success
}
