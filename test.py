from bcc import BPF

prog='''
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

BPF_HASH(start, u64);


int do_recv(struct pt_regs *ctx, struct sk_buff *skb)
{
    int dev_index = skb->dev->ifindex;
    u64 ts, *tsp, delta;

    u64 recv_key = 2;

    if (dev_index == OUTER_DEV_INDEX) {
        ts = bpf_ktime_get_ns();
        start.update(&recv_key, &ts);
    } else if (dev_index == INNER_DEV_INDEX) {
        tsp = start.lookup(&recv_key);
        if (tsp != 0) {
            delta = bpf_ktime_get_ns() - *tsp;
            bpf_trace_printk("recv latency: %llu \\n ", delta);
        }
        start.delete(&recv_key);
    }
    return 0;
}


int do_send(struct pt_regs *ctx, struct sk_buff *skb)
{
    int dev_index = skb->dev->ifindex;
    u64 ts, *tsp, delta;

    u64 send_key = 1;

    if (dev_index == INNER_DEV_INDEX) {
        ts = bpf_ktime_get_ns();
        start.update(&send_key, &ts);
    } else if (dev_index == OUTER_DEV_INDEX) {
        tsp = start.lookup(&send_key);
        if (tsp != 0) {
            delta = bpf_ktime_get_ns() - *tsp;
            bpf_trace_printk("send latency: %llu \\n ", delta);
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
print("Watching for latencies")


b.trace_print()
