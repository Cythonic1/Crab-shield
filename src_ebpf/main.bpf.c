#include "./aheader.h"

extern int bpf_strstr(const char* s1__ign, const char* s2__ign) __weak __ksym;

#define MAX_CHUNK_SIZE 64       // MUST be <= 25 for verifier safety
#define MAX_CHUNK_SIZE_MID 128  // MUST be <= 25 for verifier safety
#define MAX_CHUNK_SIZE_BIG 256  // MUST be <= 25 for verifier safety
#define MAX_ENTRIES 102400
#define SAMPLE_DATA_SIZE 256
#define MAX_PATH_NUMBER 5    // This define number of maximum path to monitor these path include any nested
#define MAX_PATH_LENGTH 126  // Add this
struct EntropyBuf {
    char buf[SAMPLE_DATA_SIZE];
    bool is_handled;  // This feild define is we need to get another sample or not. if true then we finish with this
                      // this sample...
    __u64 size_of_written_data;
    bool ready_to_be_handled;  // This feild tell us if the buffer is complete and the user space can use it now.
};

// Remove read_sys and write_sys as they match the write attempts and read attempts
struct ProcInfo {
    __u64 open_syscall;  // counts both open and openat
    __u64 close_syscall;
    __u64 delete_syscall;
};

typedef enum EventType {
    EVENT_OPEN = 1,
    EVENT_CLOSE = 3,
    EVENT_DELETE = 5,
} EventType;

struct Event {
    __u32 pid;
    EventType event_type;  // 1=open/openat, 2=write, 3=close
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB
} EventsMap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);  // pid (tgid)
    __type(value, struct ProcInfo);
} ProcMap SEC(".maps");

struct ConfigUser {
    // Define the paths program going to monitor
    char paths[MAX_PATH_NUMBER][MAX_PATH_LENGTH];
    __u32 number_of_entries;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ConfigUser);
} ConfigMap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);  // pid (tgid)
    __type(value, struct EntropyBuf);
} BuffersMap SEC(".maps");

struct loop_ctx {
    char path[MAX_PATH_LENGTH];
};

static __always_inline const struct ConfigUser* const get_config() {
    __u32 key = 0;

    const struct ConfigUser* config;
    config = bpf_map_lookup_elem(&ConfigMap, &key);
    if (!config) return NULL;
    // bpf_printk("Config found with number of entries: %u\n", config->number_of_entries);

    return config;
}

// Function used to insert event into the ring buffer return 0 on faliure and 1 on secssus
static __always_inline int insert_event(__u32 pid, EventType event_type) {
    struct Event* reserved_event = bpf_ringbuf_reserve(&EventsMap, sizeof(struct Event), 0);
    if (!reserved_event) {
        bpf_printk("The ring buffer is fulled..");
        return 1;
    }
    reserved_event->pid = pid;
    reserved_event->event_type = event_type;
    bpf_ringbuf_submit(reserved_event, 0);
    return 0;
}

static long is_path_protected(__u64 index, void* ctx) {
    struct loop_ctx* loop_ctx = ctx;
    const struct ConfigUser* config = get_config();

    // Step 1: bound the index
    if (index >= MAX_PATH_NUMBER) return 0;

    // Step 2: load pointer safely
    const char* path_config = config->paths[index];
    if (!path_config) {
        bpf_printk("in valid path with index of %d and path of %s", index, loop_ctx->path);
        return 0;
    }

    // Step 3: check if path matches
    if (bpf_strstr(loop_ctx->path, path_config) != -ENOENT) {
        bpf_printk("path of %s match the given path %s", loop_ctx->path, path_config);
        // args->found = true;
        return 1;
    }

    return 0;
}

static __always_inline struct ProcInfo* get_proc_info(__u32 pid, bool create_new_entry) {
    struct ProcInfo* info = bpf_map_lookup_elem(&ProcMap, &pid);
    if (info == NULL && create_new_entry) {
        struct ProcInfo zero = {0};

        bpf_map_update_elem(&ProcMap, &pid, &zero, BPF_NOEXIST);
        info = bpf_map_lookup_elem(&ProcMap, &pid);
        return info;
    } else if (info != NULL)
        return info;

    return NULL;
}

static __always_inline struct EntropyBuf* get_buf_info(__u32 pid) {
    struct EntropyBuf* buf = bpf_map_lookup_elem(&BuffersMap, &pid);
    if (!buf) {
        struct EntropyBuf init = {.ready_to_be_handled = false, .is_handled = true, .size_of_written_data = 0};

        bpf_map_update_elem(&BuffersMap, &pid, &init, BPF_NOEXIST);
        buf = bpf_map_lookup_elem(&BuffersMap, &pid);
        return buf;
    } else if (buf) {
        return buf;
    }
    return NULL;
}

SEC("tp/syscalls/sys_enter_unlink")
int trace_enter_unlink(struct trace_event_raw_sys_enter* ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    char buf[32];
    bpf_get_current_comm(buf, sizeof(buf));

    const struct ConfigUser* config = get_config();
    if (config == NULL) {
        bpf_printk("no config found returning\n");
        return 0;
    }

    const char* user_path = (const char*)BPF_CORE_READ(ctx, args[0]);
    struct loop_ctx ctx_loop;

    bpf_probe_read_str(ctx_loop.path, MAX_PATH_LENGTH, user_path);

    long ret = bpf_loop(config->number_of_entries, is_path_protected, &ctx_loop, 0);

    if (ret < config->number_of_entries) {
        bpf_printk("Process with command of %s deleted protected path %s", buf, user_path);
        struct ProcInfo* element = get_proc_info(pid, true);
        if (!element) return 0;
        insert_event(pid, EVENT_DELETE);
        __sync_fetch_and_add(&element->delete_syscall, 1);
        return 0;
    }

    return 0;
}

SEC("tp/syscalls/sys_enter_unlinkat")
int trace_enter_unlinkat(struct trace_event_raw_sys_enter* ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    char buf[32];
    bpf_get_current_comm(buf, sizeof(buf));

    const struct ConfigUser* config = get_config();
    if (config == NULL) {
        bpf_printk("no config found returning\n");
        return 0;
    }

    // unlinkat: args[0] = dirfd, args[1] = pathname, args[2] = flags
    const char* user_path = (const char*)BPF_CORE_READ(ctx, args[1]);
    struct loop_ctx ctx_loop = {};

    bpf_probe_read_str(ctx_loop.path, MAX_PATH_LENGTH, user_path);

    long ret = bpf_loop(config->number_of_entries, is_path_protected, &ctx_loop, 0);

    if (ret < config->number_of_entries) {
        bpf_printk("Process with command of %s deleted protected path %s", buf, user_path);
        struct ProcInfo* element = get_proc_info(pid, true);
        insert_event(pid, EVENT_DELETE);
        if (!element) return 0;
        __sync_fetch_and_add(&element->delete_syscall, 1);
        return 0;
    }

    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int trace_enter_read(struct trace_event_raw_sys_enter* ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct ProcInfo* element = get_proc_info(pid, false);

    if (element == NULL) return 0;

    return 0;
}

SEC("tp/syscalls/sys_enter_close")
int trace_enter_close(struct trace_event_raw_sys_enter* ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct ProcInfo* element = get_proc_info(pid, false);

    if (element == NULL) return 0;

    __sync_fetch_and_add(&element->close_syscall, 1);
    insert_event(pid, EVENT_CLOSE);
    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int trace_enter_write(struct trace_event_raw_sys_enter* ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct ProcInfo* element = get_proc_info(pid, false);
    if (!element) return 0;

    const char* user_buffer = (const char*)BPF_CORE_READ(ctx, args[1]);
    if (user_buffer == NULL) return 0;

    const __u64 data_size = (const __u64)BPF_CORE_READ(ctx, args[2]);

    struct EntropyBuf* element_buf = get_buf_info(pid);
    if (element_buf == NULL) {
        bpf_printk("Error getting the buffer info");
        return 0;
    }
    bpf_printk("size of the written data %llu -- for process %u", data_size, pid);

    // Only process if buffer is ready for new data
    if (element_buf->is_handled == true && element_buf->ready_to_be_handled == false) {
        __u64 written = element_buf->size_of_written_data;  // 97
                                                            // 159 / 41

        // Case 1: Large write with empty buffer
        // if (data_size > SAMPLE_DATA_SIZE && written == 0) {
        //     bpf_probe_read_user(element_buf->buf, SAMPLE_DATA_SIZE, user_buffer);
        //     element_buf->size_of_written_data = SAMPLE_DATA_SIZE;
        //     element_buf->is_handled = false;
        //     element_buf->ready_to_be_handled = true;
        //     return 0;
        // }
        //
        // // Case 2: Small write with empty buffer
        // if (data_size < SAMPLE_DATA_SIZE && written == 0) {
        //     __u64 size = data_size;  // 41
        //     if (size > SAMPLE_DATA_SIZE) {
        //         size = SAMPLE_DATA_SIZE;
        //     }
        //     bpf_probe_read_user(element_buf->buf, size, user_buffer);
        //     element_buf->size_of_written_data = size;
        //     element_buf->is_handled = false;
        //     element_buf->ready_to_be_handled = false;
        //     return 0;
        // }

        __u32 remaining = data_size;

        /* Cap to verifier-safe max */
        if (remaining > MAX_CHUNK_SIZE) {
            remaining = MAX_CHUNK_SIZE;
        }
        if (remaining > MAX_CHUNK_SIZE_MID) {
            remaining = MAX_CHUNK_SIZE_MID;
        }

        if (remaining > MAX_CHUNK_SIZE_BIG) {
            remaining = MAX_CHUNK_SIZE_BIG;
        }

        if (remaining > 0) {
            bpf_probe_read_user(element_buf->buf, remaining, user_buffer);
            element_buf->size_of_written_data = remaining;
            element_buf->is_handled = false;
            element_buf->ready_to_be_handled = true;
            return 0;
        }

        // Case 3: Buffer has partial data, need to append
        // if (written != 0) {
        //     /* written must be strictly less than buffer size */
        //     if (written >= SAMPLE_DATA_SIZE) {
        //         element_buf->size_of_written_data = SAMPLE_DATA_SIZE;
        //         element_buf->ready_to_be_handled = true;
        //         element_buf->is_handled = false;
        //         return 0;
        //     }
        //
        //     /* remaining bytes in buffer */
        //     __u64 remaining = SAMPLE_DATA_SIZE - written;  // 159
        //
        //     // /* hard verifier bound: remaining <= MAX_CHUNK_SIZE */
        //     // if (remaining > MAX_CHUNK_SIZE) {
        //     //     remaining = MAX_CHUNK_SIZE;
        //     // }
        //
        //     if (remaining <= SAMPLE_DATA_SIZE) {
        //         bpf_probe_read_user(&element_buf->buf[written], remaining, user_buffer);
        //         element_buf->size_of_written_data = SAMPLE_DATA_SIZE;
        //         element_buf->ready_to_be_handled = true;
        //         element_buf->is_handled = false;
        //         return 0;
        //     }
        //     // bpf_probe_read_user(&element_buf->buf[written], remaining, user_buffer);
        //     //
        //     // /* update written count */
        //     // written += remaining;
        //     // if (written > SAMPLE_DATA_SIZE) {
        //     //     written = SAMPLE_DATA_SIZE;
        //     // }
        //     //
        //     // element_buf->size_of_written_data = written;
        //     //
        //     // /* mark readiness */
        //     // if (written == SAMPLE_DATA_SIZE) {
        //     //     element_buf->ready_to_be_handled = true;
        //     // } else {
        //     //     element_buf->ready_to_be_handled = false;
        //     // }
        //     //
        //     // element_buf->is_handled = false;
        //     // return 0;
    } else {
        bpf_printk("Buffer not ready: is_handled=%d, ready_to_be_handled=%d", element_buf->is_handled,
                   element_buf->ready_to_be_handled);
    }
    return 0;
}

// open("atha", option, perm)
SEC("tp/syscalls/sys_enter_open")
int trace_enter_open(struct trace_event_raw_sys_enter* ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    char buf[32];
    bpf_get_current_comm(buf, sizeof(buf));

    const struct ConfigUser* config = get_config();
    if (config == NULL) {
        bpf_printk("no config found returning\n");
        return 0;
    }

    const char* user_path = (const char*)BPF_CORE_READ(ctx, args[1]);

    struct loop_ctx ctx_loop;

    bpf_probe_read_str(ctx_loop.path, MAX_PATH_LENGTH, user_path);

    long ret = bpf_loop(config->number_of_entries, is_path_protected, &ctx_loop, 0);

    if (ret < config->number_of_entries) {
        insert_event(pid, EVENT_OPEN);
        bpf_printk("Process with command of %s accessed protected path %s", buf, user_path);
        struct ProcInfo* element = get_proc_info(pid, true);
        if (!element) return 0;
        __sync_fetch_and_add(&element->open_syscall, 1);
        return 0;
    }

    return 0;
}

static long print_config(__u64 index, void* ctx) {
    const struct ConfigUser* config = get_config();
    if (config == NULL) {
        bpf_printk("Error finding the config");
        return 1;
    }

    if (index >= MAX_PATH_NUMBER)  // verifier needs this!
        return 1;

    if (!config->paths[index]) {
        bpf_printk("Invalid path at index %llu\n", index);
        return 1;
    }

    bpf_printk("path provided: %s\n", config->paths[index]);
    bpf_printk("number of paths: %d\n", config->number_of_entries);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter* ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    char buf[32];
    bpf_get_current_comm(buf, sizeof(buf));

    const struct ConfigUser* config = get_config();
    if (config == NULL) {
        bpf_printk("no config found returning\n");
        return 0;
    }

    const char* user_path = (const char*)BPF_CORE_READ(ctx, args[1]);
    //
    struct loop_ctx ctx_loop = {};

    bpf_probe_read_str(ctx_loop.path, MAX_PATH_LENGTH, user_path);

    long ret = bpf_loop(config->number_of_entries, is_path_protected, &ctx_loop, 0);

    if (ret < config->number_of_entries) {
        insert_event(pid, EVENT_OPEN);
        bpf_printk("Process with command of %s accessed protected path %s", buf, user_path);
        struct ProcInfo* element = get_proc_info(pid, true);

        if (!element) return 0;
        __sync_fetch_and_add(&element->open_syscall, 1);
        return 0;
    }

    return 0;
}
