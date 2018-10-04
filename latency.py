from bcc import BPF
import ctypes as ct

prog='''
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

struct latency_t {
    u64 ts;
    u64 ns;
    u32 dir; // 1: send, 2: recv
};
BPF_PERF_OUTPUT(events);

BPF_HASH(start, u64);


int do_recv(struct pt_regs *ctx, struct sk_buff *skb)
{
    int dev_index = skb->dev->ifindex;
    u64 ts, *tsp, delta;
    struct latency_t lat = {};

    u64 recv_key = 2;

    if (dev_index == OUTER_DEV_INDEX) {
        ts = bpf_ktime_get_ns();
        start.update(&recv_key, &ts);
    } else if (dev_index == INNER_DEV_INDEX) {
        tsp = start.lookup(&recv_key);
        if (tsp != 0) {
            lat.ts = bpf_ktime_get_ns();
            lat.ns = lat.ts - *tsp;
            lat.dir = recv_key;
            events.perf_submit(ctx, &lat, sizeof(lat));
        }
        start.delete(&recv_key);
    }
    return 0;
}


int do_send(struct pt_regs *ctx, struct sk_buff *skb)
{
    int dev_index = skb->dev->ifindex;
    u64 ts, *tsp, delta;
    struct latency_t lat = {};

    u64 send_key = 1;

    if (dev_index == INNER_DEV_INDEX) {
        ts = bpf_ktime_get_ns();
        start.update(&send_key, &ts);
    } else if (dev_index == OUTER_DEV_INDEX) {
        tsp = start.lookup(&send_key);
        if (tsp != 0) {
            lat.ts = bpf_ktime_get_ns();
            lat.ns = lat.ts - *tsp;
            lat.dir = send_key;
            events.perf_submit(ctx, &lat, sizeof(lat));
        }
        start.delete(&send_key);
    }
    return 0;
}
'''

outer_dev_index = 3
inner_dev_index = 5

prog = prog.replace('OUTER_DEV_INDEX', str(outer_dev_index))
prog = prog.replace('INNER_DEV_INDEX', str(inner_dev_index))

b = BPF(text=prog)

b.attach_kprobe(event="__netif_receive_skb_core", fn_name="do_recv")
b.attach_kprobe(event="dev_queue_xmit", fn_name="do_send")

class Latency(ct.Structure):
    _fields_ = [("ts", ct.c_ulonglong),
                ("ns", ct.c_ulonglong),
                ("dir", ct.c_ulong)]
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Latency)).contents
    print("ts: %d, ns: %d, dir: %d" % (event.ts, event.ns, event.dir))

b["events"].open_perf_buffer(print_event)

print("Watching for latencies")

while 1:
    b.perf_buffer_poll()
