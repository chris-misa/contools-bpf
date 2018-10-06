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
BPF_HASH(addr, u64, struct sk_buff *);
BPF_HASH(prev_len, u64, unsigned int);


TRACEPOINT_PROBE(net, netif_receive_skb)
{
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    struct net_device *dev = NULL;
    int dev_index;

    struct sk_buff **addrp;
    u64 ts, *tsp, delta;
    struct latency_t lat = {};

    u64 send_key = 1;
    u64 recv_key = 2;

    // Make sure we're expecting an echo reply
    if (on_wire.lookup(&send_key) != 0) {

	// Get the device index
        bpf_probe_read(&dev, sizeof(skb->dev), ((char *)skb) + offsetof(typeof(*skb), dev));
        bpf_probe_read(&dev_index, sizeof(int), ((char *)dev) + offsetof(typeof(*dev), ifindex));

        if (dev_index == OUTER_DEV_INDEX) {
            ts = bpf_ktime_get_ns();
            start.update(&recv_key, &ts);
            addr.update(&recv_key, &skb);

        } else if (dev_index == INNER_DEV_INDEX) {
            addrp = addr.lookup(&recv_key);
            if (addrp != 0 && *addrp == skb) {
                lat.ts = bpf_ktime_get_ns();
                tsp = start.lookup(&recv_key);
		if (tsp != 0) {
                    lat.ns = lat.ts - *tsp;
                    lat.dir = recv_key;
                    events.perf_submit(args, &lat, sizeof(lat));
		}
                addr.delete(&recv_key);
                on_wire.delete(&send_key);
            }
        }
    }
    return 0;
}

TRACEPOINT_PROBE(net, net_dev_start_xmit)
{
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    struct net_device *dev = NULL;
    int dev_index;

    struct sk_buff **addrp;
    u64 ts, *tsp, delta;
    struct latency_t lat = {};

    u64 send_key = 1;

    // Get the device index
    bpf_probe_read(&dev, sizeof(skb->dev), ((char *)skb) + offsetof(typeof(*skb), dev));
    bpf_probe_read(&dev_index, sizeof(int), ((char *)dev) + offsetof(typeof(*dev), ifindex));

    if (dev_index == INNER_DEV_INDEX) {
        ts = bpf_ktime_get_ns();
        start.update(&send_key, &ts);
        addr.update(&send_key, &skb);

    } else if (dev_index == OUTER_DEV_INDEX) {
	addrp = addr.lookup(&send_key);
        if (addrp != 0 && *addrp == skb) {
            lat.ts = bpf_ktime_get_ns();
            tsp = start.lookup(&send_key);
	    if (tsp != 0) {
                lat.ns = lat.ts - *tsp;
                lat.dir = send_key;
                events.perf_submit(args, &lat, sizeof(lat));
                on_wire.update(&send_key,&send_key);
	    }
	    addr.delete(&send_key);
        }
    }
    return 0;
}
