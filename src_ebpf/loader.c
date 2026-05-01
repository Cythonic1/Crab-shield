#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

#include "skel.h"

#define MAX_PATH_NUMBER 5

typedef enum EventType {
    EVENT_OPEN = 1,
    EVENT_WRITE = 2,
    EVENT_CLOSE = 3,
    EVENT_READ = 4,
    EVENT_DELETE = 5,
} EventType;

const char* event_type_to_string(EventType event) {
    switch (event) {
        case EVENT_OPEN:
            return "EVENT_OPEN";
        case EVENT_WRITE:
            return "EVENT_WRITE";
        case EVENT_CLOSE:
            return "EVENT_CLOSE";
        case EVENT_READ:
            return "EVENT_READ";
        case EVENT_DELETE:
            return "EVENT_DELETE";
        default:
            return "UNKNOWN_EVENT";
    }
}

struct Event {
    __u32 pid;
    EventType event_type;
    __u64 timestamp;
};

struct ConfigUser {
    char paths[MAX_PATH_NUMBER][126];
    __u32 number_of_entries;
};

static int ring_buffer_callback(void* ctx, void* data, size_t size) {
    struct Event* event = data;

    printf("PID: %u\n", event->pid);
    printf("Event: %s\n", event_type_to_string(event->event_type));
    printf("Timestamp: %llu\n\n", event->timestamp);

    return 0;
}

int main(int argc, char** argv) {
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    struct main_bpf* skel = NULL;
    struct ring_buffer* rb = NULL;
    struct bpf_link* openssl_link = NULL;
    int map_fd;
    int key = 0;
    int err;

    /* Increase rlimit */
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit");
        return 1;
    }

    /* Load BPF skeleton */
    skel = main_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    /* Push config to BPF map */
    map_fd = bpf_map__fd(skel->maps.ConfigMap);

    struct ConfigUser cfg = {
        .paths = {"/root/", "/var/", "/something/", "/another/", "/yoooo/"},
        .number_of_entries = 5,
    };

    if (bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY)) {
        perror("bpf_map_update_elem");
        goto cleanup;
    }

    printf("Config pushed successfully\n");

    /* Setup ring buffer */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.EventsMap), ring_buffer_callback, NULL, NULL);

    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* ---------- MANUAL OPENSSL UPROBE ATTACH ---------- */
    openssl_link = bpf_program__attach_uprobe(skel->progs.evp_encypt,             /* BPF program */
                                              false,                              /* entry uprobe */
                                              -1,                                 /* any PID */
                                              "/usr/lib/libcrypto.so.3", 0x1a2c10 /* symbol-based attach */
    );

    if (!openssl_link) {
        fprintf(stderr, "Failed to attach EVP_PKEY_encrypt uprobe\n");
        goto cleanup;
    }

    // main_bpf__attach(skel);
    printf("Attached uprobe to EVP_PKEY_encrypt\n");
    /* ------------------------------------------------- */

    /* Poll events */
    while (1) {
        err = ring_buffer__poll(rb, 1000);
        if (err == -EINTR) {
            printf("Exiting...\n");
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Ring buffer error: %d\n", err);
            break;
        }
    }

cleanup:
    bpf_link__destroy(openssl_link);
    ring_buffer__free(rb);
    main_bpf__destroy(skel);
    return 0;
}
