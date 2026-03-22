// include/sentinel_vmi.h
#pragma once

#include <stdint.h>
#include <stddef.h>

// Forward declarations
struct vmi_session;

// kvmi_setup.c
struct vmi_session *kvmi_setup(const char *vm_name);
void kvmi_teardown(struct vmi_session *session);

// memory.c
int  vmi_read_physical(struct vmi_session *s,
                       uint64_t gpa,
                       void *buf,
                       size_t size);
int  vmi_gva_to_gpa(struct vmi_session *s,
                    uint64_t gva,
                    uint64_t *gpa);

// task_walker.c
void task_walker_dump(struct vmi_session *s);
int  task_walker_find_pid(struct vmi_session *s,
                          uint32_t pid,
                          uint64_t *task_addr);

// npt_guard.c
int  npt_guard_arm(struct vmi_session *s);
void npt_guard_disarm(struct vmi_session *s);
void npt_guard_handle_events(struct vmi_session *s);

// npf_handler.c
int  npf_handler_init(struct vmi_session *s);
void npf_handler_process(struct vmi_session *s,
                         uint64_t gpa,
                         int write_access);

// bridge.c
int  bridge_init(void);
void bridge_teardown(void);
void bridge_signal_malicious(uint32_t pid,
                             const char *reason);
void bridge_flush_alerts(void);
