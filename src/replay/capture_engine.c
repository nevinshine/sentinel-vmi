// src/replay/capture_engine.c — Stage 3C Semantic Replay Engine
//
// Dumps sensor ring events into highly stable, chunked .seg files
// using a versioned packed ABI and delta-encoded timestamps.

#include "sentinel_vmi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

#define MAX_EVENTS_PER_SEGMENT 100000

static int current_segment_index = 0;
static uint64_t last_timestamp_ns = 0;

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Write the sensor ring content to a chunked .seg file
int vmi_capture_ring_to_disk(struct sensor_ring *ring, const char *capture_dir) {
    if (!ring || !capture_dir) return -1;
    
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/capture_%05d.seg", capture_dir, current_segment_index++);
    
    int fd = open(filepath, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0) {
        return -1;
    }
    
    uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
    uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    
    if (head == tail) {
        close(fd);
        return 0; // Empty
    }
    
    // Count events
    uint32_t num_events = (tail >= head) ? (tail - head) : (SENSOR_RING_SIZE - head + tail);
    if (num_events > MAX_EVENTS_PER_SEGMENT) {
        num_events = MAX_EVENTS_PER_SEGMENT; // Cap per segment
    }
    
    uint64_t current_ns = get_time_ns();
    if (last_timestamp_ns == 0) last_timestamp_ns = current_ns;
    
    struct capture_header header = {0};
    header.magic = SENTINEL_CAPTURE_MAGIC;
    header.version_major = 1;
    header.version_minor = 0;
    header.capture_start_ns = current_ns;
    header.event_count = num_events;
    header.semantic_event_size = sizeof(struct replay_semantic_event_v1);
    header.header_size = sizeof(struct capture_header);
    header.compression_mode = 0; // Uncompressed inline, compressed asynchronously later
    
    if (write(fd, &header, sizeof(header)) != sizeof(header)) {
        close(fd);
        return -1;
    }
    
    uint32_t curr = head;
    uint32_t written = 0;
    
    while (curr != tail && written < num_events) {
        struct semantic_event *ev = &ring->entries[curr];
        
        struct replay_semantic_event_v1 rev = {0};
        
        // Delta encoding for extreme redundancy compression
        uint64_t event_time = get_time_ns();
        rev.delta_ns = (uint32_t)(event_time - last_timestamp_ns);
        last_timestamp_ns = event_time;
        
        rev.causal_id = ev->causal_id;
        rev.cr3 = ev->cr3;
        rev.rip = ev->rip;
        rev.event_type = ev->event_type;
        rev.energy = ev->semantic_energy;
        rev.confidence_q8 = F32_TO_Q8_8(1.0f);
        rev.survivability = ev->survivability;
        rev.namespace_hash = 0; // Placeholder until namespace mapping is complete
        
        if (write(fd, &rev, sizeof(rev)) != sizeof(rev)) {
            break;
        }
        
        curr = (curr + 1) % SENSOR_RING_SIZE;
        written++;
    }
    
    header.capture_end_ns = get_time_ns();
    lseek(fd, 0, SEEK_SET); // Overwrite header with final end_ns
    write(fd, &header, sizeof(header));
    
    close(fd);
    
    // Drop processed events from ring
    atomic_store_explicit(&ring->head, curr, memory_order_release);
    
    return 0;
}
