// src/kvmi_setup.c - Phase 1: KVM Introspection Session Establishment
//
// Attaches to a running QEMU/KVM VM, performs a real control-channel
// handshake (QMP capability negotiation), discovers live vCPU handles,
// and builds a best-effort guest memory map from /proc/<pid>/maps.

#include "sentinel_vmi.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define VMI_MAX_MEMSLOTS 256
#define QMP_REPLY_MAX 4096
#define MIN_RAM_MAPPING_SIZE (2ULL * 1024ULL * 1024ULL)

static int is_numeric_name(const char *s) {
    if (!s || !*s)
        return 0;

    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p))
            return 0;
    }
    return 1;
}

static int read_pid_cmdline(int pid, char *out, size_t out_sz) {
    if (pid <= 0 || !out || out_sz == 0)
        return -1;

    char path[64];
    int n = snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return -1;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    ssize_t nr = read(fd, out, out_sz - 1);
    close(fd);
    if (nr <= 0)
        return -1;

    for (ssize_t i = 0; i < nr; i++) {
        if (out[i] == '\0')
            out[i] = ' ';
    }
    out[nr] = '\0';
    return 0;
}

// Find the QEMU process for a VM name by scanning /proc/<pid>/cmdline.
static int find_vm_pid(const char *vm_name) {
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("[VMI-Setup] opendir /proc");
        return -1;
    }

    struct dirent *entry;
    char cmdline[4096];

    while ((entry = readdir(proc)) != NULL) {
        if (!is_numeric_name(entry->d_name))
            continue;

        int pid = atoi(entry->d_name);
        if (read_pid_cmdline(pid, cmdline, sizeof(cmdline)) < 0)
            continue;

        if (strstr(cmdline, "qemu") && strstr(cmdline, vm_name)) {
            closedir(proc);
            printf("[VMI-Setup] Found VM '%s' at PID %d\n", vm_name, pid);
            return pid;
        }
    }

    closedir(proc);
    return -1;
}

static int open_kvm_device(void) {
    int fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        perror("[VMI-Setup] open /dev/kvm");
        return -1;
    }

    int api_ver = ioctl(fd, KVM_GET_API_VERSION, 0);
    if (api_ver != KVM_API_VERSION) {
        fprintf(stderr, "[VMI-Setup] KVM API version mismatch: expected %d, got %d\n",
                KVM_API_VERSION, api_ver);
        close(fd);
        return -1;
    }

    printf("[VMI-Setup] /dev/kvm opened (API v%d)\n", api_ver);
    return fd;
}

static int open_pid_fd(int pid, const char *fd_name) {
    char path[64];
    int n = snprintf(path, sizeof(path), "/proc/%d/fd/%s", pid, fd_name);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return -1;

    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        fd = open(path, O_RDONLY | O_CLOEXEC);

    return fd;
}

// Duplicate a target FD owned by QEMU by matching /proc/<pid>/fd symlink text.
static int duplicate_fd_by_link_target(int qemu_pid, const char *needle) {
    char fd_dir[64];
    int n = snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", qemu_pid);
    if (n <= 0 || (size_t)n >= sizeof(fd_dir))
        return -1;

    DIR *dir = opendir(fd_dir);
    if (!dir)
        return -1;

    struct dirent *entry;
    char link_path[128];
    char link_target[512];

    while ((entry = readdir(dir)) != NULL) {
        if (!is_numeric_name(entry->d_name))
            continue;

        n = snprintf(link_path, sizeof(link_path), "%s/%s", fd_dir, entry->d_name);
        if (n <= 0 || (size_t)n >= sizeof(link_path))
            continue;

        ssize_t nr = readlink(link_path, link_target, sizeof(link_target) - 1);
        if (nr < 0)
            continue;

        link_target[nr] = '\0';
        if (!strstr(link_target, needle))
            continue;

        int fd = open_pid_fd(qemu_pid, entry->d_name);
        if (fd >= 0) {
            closedir(dir);
            return fd;
        }
    }

    closedir(dir);
    return -1;
}

static int discover_vcpu_fds(struct vmi_session *session, int qemu_pid) {
    char fd_dir[64];
    int n = snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", qemu_pid);
    if (n <= 0 || (size_t)n >= sizeof(fd_dir))
        return 0;

    DIR *dir = opendir(fd_dir);
    if (!dir)
        return 0;

    struct dirent *entry;
    char link_path[128];
    char link_target[512];
    int count = 0;

    while ((entry = readdir(dir)) != NULL && count < VMI_MAX_VCPUS) {
        if (!is_numeric_name(entry->d_name))
            continue;

        n = snprintf(link_path, sizeof(link_path), "%s/%s", fd_dir, entry->d_name);
        if (n <= 0 || (size_t)n >= sizeof(link_path))
            continue;

        ssize_t nr = readlink(link_path, link_target, sizeof(link_target) - 1);
        if (nr < 0)
            continue;

        link_target[nr] = '\0';
        if (!strstr(link_target, "anon_inode:kvm-vcpu"))
            continue;

        int fd = open_pid_fd(qemu_pid, entry->d_name);
        if (fd < 0)
            continue;

        session->vcpu_fds[count++] = fd;
    }

    closedir(dir);
    return count;
}

static int parse_unix_socket_spec(const char *spec, char *path, size_t path_sz) {
    static const char prefix[] = "unix:";

    if (!spec || !path || path_sz == 0)
        return -1;
    if (strncmp(spec, prefix, sizeof(prefix) - 1) != 0)
        return -1;

    const char *start = spec + (sizeof(prefix) - 1);
    const char *end = strchr(start, ',');
    size_t len = end ? (size_t)(end - start) : strlen(start);

    if (len == 0 || len >= path_sz || len >= sizeof(((struct sockaddr_un *)0)->sun_path))
        return -1;

    memcpy(path, start, len);
    path[len] = '\0';
    return 0;
}

static int extract_qmp_path_from_cmdline(const char *cmdline, char *path, size_t path_sz) {
    if (!cmdline || !path || path_sz == 0)
        return -1;

    char tmp[4096];
    strncpy(tmp, cmdline, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    char *saveptr = NULL;
    for (char *tok = strtok_r(tmp, " ", &saveptr);
         tok != NULL;
         tok = strtok_r(NULL, " ", &saveptr)) {
        const char *spec = NULL;

        if (strcmp(tok, "-qmp") == 0) {
            char *arg = strtok_r(NULL, " ", &saveptr);
            if (!arg)
                break;
            spec = arg;
        } else if (strncmp(tok, "-qmp=", 5) == 0) {
            spec = tok + 5;
        }

        if (spec && parse_unix_socket_spec(spec, path, path_sz) == 0)
            return 0;
    }

    return -1;
}

static int socket_write_all(int fd, const char *buf, size_t len) {
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, buf + written, len - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        written += (size_t)n;
    }
    return 0;
}

static int socket_read_text(int fd, char *buf, size_t buf_sz) {
    if (!buf || buf_sz < 2)
        return -1;

    ssize_t n = read(fd, buf, buf_sz - 1);
    if (n <= 0)
        return -1;

    buf[n] = '\0';
    return 0;
}

// Best-effort QMP handshake used as a control-channel sanity check.
static int connect_qmp_channel(int qemu_pid) {
    char cmdline[4096];
    if (read_pid_cmdline(qemu_pid, cmdline, sizeof(cmdline)) < 0)
        return -1;

    char qmp_path[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
    if (extract_qmp_path_from_cmdline(cmdline, qmp_path, sizeof(qmp_path)) < 0)
        return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct timeval tv = {
        .tv_sec = 1,
        .tv_usec = 0,
    };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t qmp_len = strlen(qmp_path);
    if (qmp_len >= sizeof(addr.sun_path)) {
        close(fd);
        return -1;
    }
    memcpy(addr.sun_path, qmp_path, qmp_len + 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    char reply[QMP_REPLY_MAX];
    if (socket_read_text(fd, reply, sizeof(reply)) < 0) {
        close(fd);
        return -1;
    }

    static const char qmp_caps[] =
        "{\"execute\":\"qmp_capabilities\"}\n";
    if (socket_write_all(fd, qmp_caps, sizeof(qmp_caps) - 1) < 0) {
        close(fd);
        return -1;
    }

    if (socket_read_text(fd, reply, sizeof(reply)) < 0) {
        close(fd);
        return -1;
    }

    if (!strstr(reply, "\"return\"")) {
        close(fd);
        return -1;
    }

    printf("[VMI-Setup] QMP handshake complete (%s)\n", qmp_path);
    return fd;
}

static int is_candidate_ram_map(const char *perms, const char *path, uint64_t span) {
    if (!perms)
        return 0;
    if (perms[0] != 'r' || perms[1] != 'w')
        return 0;
    if (span < MIN_RAM_MAPPING_SIZE)
        return 0;
    if (!path || path[0] == '\0')
        return 0;

    if (strstr(path, "[stack]") || strstr(path, "[heap]") ||
        strstr(path, "[vdso]") || strstr(path, "[vvar]") ||
        strstr(path, "[vsyscall]")) {
        return 0;
    }

    if (strstr(path, "pc.ram") || strstr(path, "memory-backend") ||
        strstr(path, "memfd:") || strstr(path, "/dev/zero")) {
        return 1;
    }

    return 0;
}

static int enumerate_memslots_from_maps(struct vmi_session *session) {
    if (!session || session->qemu_pid <= 0)
        return 0;

    char maps_path[64];
    int n = snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", session->qemu_pid);
    if (n <= 0 || (size_t)n >= sizeof(maps_path))
        return 0;

    FILE *fp = fopen(maps_path, "r");
    if (!fp)
        return 0;

    struct vmi_memslot *slots = calloc(VMI_MAX_MEMSLOTS, sizeof(*slots));
    if (!slots) {
        fclose(fp);
        return -1;
    }

    char line[2048];
    size_t count = 0;
    uint64_t next_gpa = 0;

    while (fgets(line, sizeof(line), fp) && count < VMI_MAX_MEMSLOTS) {
        unsigned long long start_ull = 0;
        unsigned long long end_ull = 0;
        char perms[5] = {0};
        char path[1024] = {0};

        int consumed = 0;
        int fields = sscanf(line,
                            "%llx-%llx %4s %*s %*s %*s %n",
                            &start_ull, &end_ull, perms, &consumed);
        if (fields < 3)
            continue;

        if (consumed > 0) {
            const char *rest = line + consumed;
            while (*rest == ' ' || *rest == '\t')
                rest++;

            size_t path_len = strcspn(rest, "\n");
            if (path_len >= sizeof(path))
                path_len = sizeof(path) - 1;
            memcpy(path, rest, path_len);
            path[path_len] = '\0';
        } else {
            path[0] = '\0';
        }

        if (end_ull <= start_ull)
            continue;

        uint64_t start = (uint64_t)start_ull;
        uint64_t end = (uint64_t)end_ull;
        uint64_t span = end - start;

        if (!is_candidate_ram_map(perms, path, span))
            continue;

        if (UINT64_MAX - next_gpa < span)
            break;

        slots[count].guest_phys_addr = next_gpa;
        slots[count].memory_size = span;
        slots[count].userspace_addr = (void *)(uintptr_t)start;
        slots[count].slot = (uint32_t)count;
        slots[count].flags = VMI_MEMSLOT_F_REMOTE_PROCESS;

        next_gpa += span;
        count++;
    }

    fclose(fp);

    if (count == 0) {
        free(slots);
        return 0;
    }

    session->memslots = slots;
    session->nr_memslots = (int)count;

    printf("[VMI-Setup] Discovered %d live memslots from QEMU mappings\n",
           session->nr_memslots);

    int preview = session->nr_memslots < 4 ? session->nr_memslots : 4;
    for (int i = 0; i < preview; i++) {
        const struct vmi_memslot *slot = &session->memslots[i];
        printf("[VMI-Setup]   slot=%u gpa=0x%lx size=0x%lx host=0x%lx\n",
               slot->slot,
               slot->guest_phys_addr,
               slot->memory_size,
               (uint64_t)(uintptr_t)slot->userspace_addr);
    }

    if (session->nr_memslots > preview) {
        printf("[VMI-Setup]   ... %d more slots\n",
               session->nr_memslots - preview);
    }

    return session->nr_memslots;
}

static int enumerate_memslots(struct vmi_session *session) {
    session->memslots = NULL;
    session->nr_memslots = 0;

    if (session->qemu_pid <= 0) {
        printf("[VMI-Setup] Memslot discovery skipped (no QEMU PID)\n");
        return 0;
    }

    int found = enumerate_memslots_from_maps(session);
    if (found < 0)
        return -1;

    if (found == 0) {
        printf("[VMI-Setup] No RAM mappings discovered in /proc/%d/maps\n",
               session->qemu_pid);
    }

    return 0;
}

struct vmi_session *kvmi_setup(const char *vm_name) {
    printf("[VMI-Setup] =======================================\n");
    printf("[VMI-Setup] Sentinel VMI - KVM Introspection Init\n");
    printf("[VMI-Setup] Target: %s\n", vm_name);
    printf("[VMI-Setup] =======================================\n");

    struct vmi_session *session = calloc(1, sizeof(struct vmi_session));
    if (!session) {
        perror("[VMI-Setup] calloc session");
        return NULL;
    }

    session->kvm_fd = -1;
    session->vm_fd = -1;
    session->qemu_pid = -1;
    session->control_fd = -1;
    for (int i = 0; i < VMI_MAX_VCPUS; i++)
        session->vcpu_fds[i] = -1;

    session->kvm_fd = open_kvm_device();
    if (session->kvm_fd < 0) {
        fprintf(stderr, "[VMI-Setup] FATAL: Cannot open /dev/kvm\n");
        free(session);
        return NULL;
    }

    int qemu_pid = find_vm_pid(vm_name);
    if (qemu_pid >= 0) {
        session->qemu_pid = qemu_pid;

        session->vm_fd = duplicate_fd_by_link_target(qemu_pid, "anon_inode:kvm-vm");
        if (session->vm_fd < 0) {
            fprintf(stderr, "[VMI-Setup] WARN: Could not duplicate kvm-vm fd from PID %d\n",
                    qemu_pid);
        }

        session->nr_vcpus = discover_vcpu_fds(session, qemu_pid);
        if (session->nr_vcpus == 0) {
            fprintf(stderr, "[VMI-Setup] WARN: No kvm-vcpu FDs discovered from PID %d\n",
                    qemu_pid);
        }

        session->control_fd = connect_qmp_channel(qemu_pid);
        if (session->control_fd < 0) {
            fprintf(stderr, "[VMI-Setup] WARN: QMP handshake unavailable for PID %d\n",
                    qemu_pid);
        }
    } else {
        fprintf(stderr, "[VMI-Setup] WARN: VM '%s' not found via /proc scan\n", vm_name);
        fprintf(stderr, "[VMI-Setup] Continuing with /dev/kvm only\n");
    }

    if (enumerate_memslots(session) < 0) {
        fprintf(stderr, "[VMI-Setup] Failed to discover memslots\n");
        kvmi_teardown(session);
        return NULL;
    }

    printf("[VMI-Setup] Session established successfully\n");
    printf("[VMI-Setup] KVM fd=%d VM fd=%d qemu_pid=%d vCPUs=%d memslots=%d control_fd=%d\n",
           session->kvm_fd,
           session->vm_fd,
           session->qemu_pid,
           session->nr_vcpus,
           session->nr_memslots,
           session->control_fd);

    return session;
}

void kvmi_teardown(struct vmi_session *session) {
    if (!session)
        return;

    printf("[VMI-Setup] Tearing down introspection session...\n");

    for (int i = 0; i < VMI_MAX_VCPUS; i++) {
        if (session->vcpu_fds[i] >= 0) {
            close(session->vcpu_fds[i]);
            session->vcpu_fds[i] = -1;
        }
    }

    if (session->control_fd >= 0) {
        close(session->control_fd);
        session->control_fd = -1;
    }

    if (session->memslots) {
        free(session->memslots);
        session->memslots = NULL;
        session->nr_memslots = 0;
    }

    if (session->vm_fd >= 0 && session->vm_fd != session->kvm_fd) {
        close(session->vm_fd);
        session->vm_fd = -1;
    }

    if (session->kvm_fd >= 0) {
        close(session->kvm_fd);
        session->kvm_fd = -1;
    }

    free(session);
    printf("[VMI-Setup] Session destroyed\n");
}
