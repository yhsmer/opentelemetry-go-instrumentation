#include "arguments.h"
#include "goroutines.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_SIZE 100
#define MAX_CONCURRENT 50

struct grpc_request_t {
    s64 goroutine;
    u64 start_time;
    u64 end_time;
    char method[MAX_SIZE];
    char target[MAX_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, s64);
	__type(value, struct grpc_request_t);
	__uint(max_entries, MAX_CONCURRENT);
} goid_to_grpc_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Injected in init
volatile const u64 clientconn_target_ptr_pos;

// This instrumentation attaches uprobe to the following function:
// func (cc *ClientConn) Invoke(ctx context.Context, method string, args, reply interface{}, opts ...CallOption) error

// Invoke 在网络上发送 RPC 请求，并在收到响应后返回。这通常由生成的代码调用。
/* Invoke 实现数据的发送和接收，并调用grpc的拦截器
    if cc.dopts.unaryInt != nil {
		return cc.dopts.unaryInt(ctx, method, args, reply, cc, invoke, opts...)
	}
   进行一些自定义的拦截工作
*/
SEC("uprobe/ClientConn_Invoke")
int uprobe_ClientConn_Invoke(struct pt_regs *ctx) {
    /* 
        uprobe Invoke
        获取method, ClientConn.Target, goroutine id, 构造grpcRequest,
        将[goroutine id, grpcRequest]存储到map goid_to_grpc_events中
    */
    // positions
    u64 clientconn_pos = 1;
    u64 context_pos = 2;
    // ptr pointer
    u64 method_ptr_pos = 4;
    u64 method_len_pos = 5;

    struct grpc_request_t grpcReq = {};
    // 获取时间戳
    grpcReq.start_time = bpf_ktime_get_ns();

    // Read Method
    // get_argument 读寄存器

    // 获取method指针所在寄存器
    void* method_ptr = get_argument(ctx, method_ptr_pos);
    // 获取method长度所在寄存器
    u64 method_len = (u64) get_argument(ctx, method_len_pos);
    u64 method_size = sizeof(grpcReq.method);
    method_size = method_size < method_len ? method_size : method_len;
    // 从method指针所在寄存器中读取method
    bpf_probe_read(&grpcReq.method, method_size, method_ptr);

    // Read ClientConn.Target
    // IP:port
    void* clientconn_ptr = get_argument(ctx, clientconn_pos);
    void* target_ptr = 0;
    bpf_probe_read(&target_ptr, sizeof(target_ptr), (void *)(clientconn_ptr+(clientconn_target_ptr_pos)));
    u64 target_len = 0;
    bpf_probe_read(&target_len, sizeof(target_len), (void *)(clientconn_ptr+(clientconn_target_ptr_pos+8)));
    u64 target_size = sizeof(grpcReq.target);
    target_size = target_size < target_len ? target_size : target_len;
    bpf_probe_read(&grpcReq.target, target_size, target_ptr);

    // Record goroutine
    // 获取goroutine id
    grpcReq.goroutine = get_current_goroutine();

    // Write event
    // ( map, key, value, flags)
    // flags: 0 exist then update, don't exist then creat
    //        1 only use when don't exist then creat
    //        2 only use when exist then update

    // groutine_id -> grpc_request
    bpf_map_update_elem(&goid_to_grpc_events, &grpcReq.goroutine, &grpcReq, 0);

    return 0;
}

SEC("uprobe/ClientConn_Invoke")
int uprobe_ClientConn_Invoke_Returns(struct pt_regs *ctx) {
    /*
        uretprobe Invoke
    */

    // thread id
    u64 current_thread = bpf_get_current_pid_tgid();
    
    // goroutine id
    void* goid_ptr = bpf_map_lookup_elem(&goroutines_map, &current_thread);
    s64 goid;
    bpf_probe_read(&goid, sizeof(goid), goid_ptr);

    void* grpcReq_ptr = bpf_map_lookup_elem(&goid_to_grpc_events, &goid);
    struct grpc_request_t grpcReq = {};
    bpf_probe_read(&grpcReq, sizeof(grpcReq), grpcReq_ptr);

    grpcReq.end_time = bpf_ktime_get_ns();

    // 通过 perf event 来保存 eBPF 数据然后再在 Go 程序中读取 perf event 中保存的数据
    // perf event 是每个CPU环形缓冲区的集合，基于CPU设计
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &grpcReq, sizeof(grpcReq));
    // 删除map中这个goroutine对应的grpc request数据
    bpf_map_delete_elem(&goid_to_grpc_events, &goid);

    return 0;
}