#include "sentinel_vmi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <inttypes.h>

#define HEKI_MAGIC 0x48454B49

struct heki_registration {
    uint32_t magic;
    uint64_t gva;
    uint32_t size;
    uint8_t  is_critical;
    char     name[32];
} __attribute__((packed));

static int heki_listen_fd = -1;
static struct vmi_session *heki_session = NULL;

int heki_server_init(struct vmi_session *session, const char *socket_path) {
    if (!session || !socket_path) return -1;

    heki_session = session;

    heki_listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (heki_listen_fd < 0) {
        perror("[HEKI] socket");
        return -1;
    }

    // Set non-blocking
    int flags = fcntl(heki_listen_fd, F_GETFL, 0);
    fcntl(heki_listen_fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    (void)unlink(socket_path);

    if (bind(heki_listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[HEKI] bind");
        close(heki_listen_fd);
        return -1;
    }

    if (listen(heki_listen_fd, 5) < 0) {
        perror("[HEKI] listen");
        close(heki_listen_fd);
        return -1;
    }

    printf("[HEKI] Bridge listening on %s\n", socket_path);
    return 0;
}

static void handle_heki_client(int client_fd) {
    struct heki_registration reg;
    ssize_t n = read(client_fd, &reg, sizeof(reg));
    
    uint8_t response = 0;

    if (n == (ssize_t)sizeof(reg) && reg.magic == HEKI_MAGIC) {
        printf("[HEKI] Received registration for map: %s\n", reg.name);
        printf("[HEKI]  - GVA: 0x%" PRIx64 "\n", reg.gva);
        printf("[HEKI]  - Size: %u\n", reg.size);
        printf("[HEKI]  - Critical: %d\n", reg.is_critical);

        uint64_t gpa = 0;
        if (heki_session->kernel_pgd == 0) {
            fprintf(stderr, "[HEKI] Error: kernel_pgd not set yet\n");
        } else if (vmi_gva_to_gpa(heki_session, heki_session->kernel_pgd, reg.gva, &gpa) < 0) {
            fprintf(stderr, "[HEKI] Error: Failed to translate GVA 0x%" PRIx64 " to GPA\n", reg.gva);
        } else {
            printf("[HEKI] Translated GVA 0x%" PRIx64 " -> GPA 0x%" PRIx64 "\n", reg.gva, gpa);
            
            // Protect the page(s)
            if (npt_guard_protect_dynamic(heki_session, gpa, reg.size, reg.is_critical, reg.name) == 0) {
                response = 1; // Success
            }
        }
    } else {
        fprintf(stderr, "[HEKI] Invalid registration payload (read %zd bytes, magic 0x%x)\n", n, reg.magic);
    }

    if (write(client_fd, &response, 1) < 0) {
        perror("[HEKI] write response failed");
    }
    close(client_fd);
}

void heki_server_poll(void) {
    if (heki_listen_fd < 0) return;

    struct sockaddr_un client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    int client_fd = accept(heki_listen_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd >= 0) {
        handle_heki_client(client_fd);
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        perror("[HEKI] accept error");
    }
}
