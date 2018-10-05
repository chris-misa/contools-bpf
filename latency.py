#!/usr/bin/python

from bcc import BPF
import ctypes as ct
import sys
import signal

USAGE="latency.py <outer device index> <inner device index>"

if len(sys.argv) != 3:
    print(USAGE)
    sys.exit(1)

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
BPF_HASH(on_wire, u32);


int do_recv(struct pt_regs *ctx, struct sk_buff *skb)
{
    int dev_index = skb->dev->ifindex;
    u64 ts, *tsp, delta;
    struct latency_t lat = {};

    u64 recv_key = 2;
    u64 send_key = 1;

    if (on_wire.lookup(&send_key) != 0) {
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
            on_wire.delete(&send_key);
        }
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
            on_wire.update(&send_key,&send_key);
        }
        start.delete(&send_key);
    }
    return 0;
}
'''

outer_dev_index = sys.argv[1]
inner_dev_index = sys.argv[2]

prog = prog.replace('OUTER_DEV_INDEX', outer_dev_index)
prog = prog.replace('INNER_DEV_INDEX', inner_dev_index)

b = BPF(text=prog)

b.attach_kprobe(event="__netif_receive_skb_core", fn_name="do_recv")
b.attach_kprobe(event="dev_queue_xmit", fn_name="do_send")

class Latency(ct.Structure):
    _fields_ = [("ts", ct.c_ulonglong),
                ("ns", ct.c_ulonglong),
                ("dir", ct.c_ulong)]


in_flight = False
send_lat = 0
def print_event(cpu, data, size):
    global in_flight, send_lat
    event = ct.cast(data, ct.POINTER(Latency)).contents
    if in_flight:
        sys.stdout.write("[%d] rtt raw_latency: %d, events_overhead: %d, end\n" \
                % (event.ts, float(event.ns + send_lat) / 1000.0, 0))
        in_flight = False
        send_lat = 0
    else:
        in_flight = True
        send_lat = event.ns

def do_exit(signum, frame):
    sys.stdout.flush()
    sys.exit(0)

def main():
    b["events"].open_perf_buffer(print_event)

    sys.stdout.write("Watching for latencies\n")

    while 1:
        b.perf_buffer_poll()

if __name__ == '__main__':
    signal.signal(signal.SIGINT, do_exit)
    main()



