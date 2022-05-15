#include "bpf_helpers.h"

#define MAX_SYSTEM_THREADS 20

struct {
    // 线程ID -> goroutine id指针地址
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, s64);
    // 最大的key容量
	__uint(max_entries, MAX_SYSTEM_THREADS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} goroutines_map SEC(".maps");

s64 get_current_goroutine() {
    // 获取当前线程ID
    u64 current_thread = bpf_get_current_pid_tgid();
    // (map,key) -> value
    void* goid_ptr = bpf_map_lookup_elem(&goroutines_map, &current_thread);
    s64 goid;
    /*
    long bpf_probe_read(void *dst, u32 size, const void *unsafe_ptr)

              Description
                     For tracing programs, safely attempt to read size
                     bytes from kernel space address unsafe_ptr and
                     store the data in dst.

                     Generally, use bpf_probe_read_user() or
                     bpf_probe_read_kernel() instead.

              Return 0 on success, or a negative error in case of
                     failure.
    */
    bpf_probe_read(&goid, sizeof(goid), goid_ptr);
    return goid;
}