// src/npt_guard.c
#include "sentinel_vmi.h"
#include <stdio.h>

int npt_guard_arm(struct vmi_session *s) {
    (void)s;
    printf("[NPT-Guard] Arming sys_call_table translation protection.\n");
    return 0;
}

void npt_guard_disarm(struct vmi_session *s) {
    (void)s;
    printf("[NPT-Guard] Disarming protection.\n");
}

void npt_guard_handle_events(struct vmi_session *s) {
    (void)s;
    // Called in main event loop, just simulate doing nothing
}
