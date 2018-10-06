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
BPF_HASH(on_wire, u64);
BPF_HASH(skbaddr, u64, struct sk_buff *);


int do_recv(struct pt_regs *ctx, struct sk_buff *skb)
{
    int dev_index = skb->dev->ifindex;
    struct sk_buff **addrp;
    u64 ts, *tsp, delta;
    struct latency_t lat = {};

    u64 recv_key = 2;
    u64 send_key = 1;

    if (on_wire.lookup(&send_key) != 0) {
        if (dev_index == OUTER_DEV_INDEX) {
            ts = bpf_ktime_get_ns();
            start.update(&recv_key, &ts);
            skbaddr.update(&recv_key, &skb);
        } else if (dev_index == INNER_DEV_INDEX) {
            tsp = start.lookup(&recv_key);
            addrp = skbaddr.lookup(&recv_key);
            if (tsp != 0 && addrp != 0 && *addrp == skb) {
                lat.ts = bpf_ktime_get_ns();
                lat.ns = lat.ts - *tsp;
                lat.dir = recv_key;
                events.perf_submit(ctx, &lat, sizeof(lat));
                start.delete(&recv_key);
            }
            on_wire.delete(&send_key);
        }
    }
    return 0;
}


int do_send(struct pt_regs *ctx, struct sk_buff *skb)
{
    int dev_index = skb->dev->ifindex;
    struct sk_buff **addrp;
    u64 ts, *tsp, delta;
    struct latency_t lat = {};

    u64 send_key = 1;

    if (dev_index == INNER_DEV_INDEX) {
        ts = bpf_ktime_get_ns();
        start.update(&send_key, &ts);
        skbaddr.update(&send_key, &skb);
    } else if (dev_index == OUTER_DEV_INDEX) {
        tsp = start.lookup(&send_key);
        addrp = skbaddr.lookup(&send_key);
        if (tsp != 0 && addrp != 0 && *addrp == skb) {
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
